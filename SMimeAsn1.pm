package SMimeAsn1;

use strict;

use Convert::ASN1;
use Data::Dumper;
use DateTime;
use IPC::Run;
use Net::SSLeay;

my $oid_asn = Convert::ASN1->new;
$oid_asn->prepare(q<
    oid ::= OBJECT IDENTIFIER
>) or die $!;

my $asn = Convert::ASN1->new;
#$asn->prepare_file("PKIX1Explicit88.asn1") or die "$!";
#$asn->prepare_file("PKIX1Implicit88.asn1") or die "$!";
#$asn->prepare_file("AttributeCertificateVersion1.asn1") or die "$!";
$asn->prepare_file("CryptographicMessageSyntax2004.asn1") or die "$!";
my $content_asn = $asn->find("ContentInfo") or die "Couldn't find ContentInfo definition: $!";
my $sig_asn = $asn->find("SignedData") or die "Couldn't find SignedData definition: $!";
my $env_asn = $asn->find("EnvelopedData") or die "Couldn't find EnvelopedData definition: $!";

my $id_signedData    = "1.2.840.113549.1.7.2";
my $id_envelopedData = "1.2.840.113549.1.7.3";
my $id_encryptedData = "1.2.840.113549.1.7.6";

my $id_smimeCapabilities = "1.2.840.113549.1.9.15";
my $smime_caps_asn = Convert::ASN1->new;
$smime_caps_asn->prepare(q<
   SMIMECapability ::= SEQUENCE {
      capabilityID OBJECT IDENTIFIER,
      parameters ANY DEFINED BY capabilityID OPTIONAL }

   SMIMECapabilities ::= SEQUENCE OF SMIMECapability
>) or die $!;
$smime_caps_asn = $smime_caps_asn->find("SMIMECapabilities") or die "Couldn't find SMIMECapabilities definition: $!";

my $id_ce_subjectAltName = "2.5.29.17";
my $subjectAlt_asn = Convert::ASN1->new;
$subjectAlt_asn->prepare(q<
-- subjectAltName EXTENSION ::= {
--     SYNTAX GeneralNames
--     IDENTIFIED BY id-ce-subjectAltName
-- }

GeneralNames ::= SEQUENCE OF GeneralName

GeneralName ::= CHOICE {
    otherName   [0] ANY,
    rfc822Name  [1] IA5String,
    dNSName     [2] IA5String,
    x400Address [3] ANY,
    directoryName   [4] ANY,
    ediPartyName    [5] EDIPartyName,
    uniformResourceIdentifier [6] IA5String,
    IPAddress   [7] OCTET STRING,
    registeredID    [8] OBJECT IDENTIFIER
}

EDIPartyName ::= SEQUENCE {
    nameAssigner [0] ANY OPTIONAL,
    partyName [1] ANY
}
>) or die $!;
$subjectAlt_asn = $subjectAlt_asn->find("GeneralNames") or die "Couldn't find GeneralNames definition: $!";

my $int_asn = Convert::ASN1->new;
$int_asn->prepare(q<V ::= INTEGER>) or die $!;

sub subject_alt_names {
    my ($cert) = @_;
    my @names;
    for my $ext (@{$cert->{'tbsCertificate'}{'extensions'}}) {
        if ($ext->{'extnID'} eq $id_ce_subjectAltName) {
            my $l = $subjectAlt_asn->decode($ext->{'extnValue'}) or die $!;
            push @names, @$l;
        }
    }
    return @names;
}

# email addresses
sub subject_alt_rfc822names {
    my ($cert) = @_;
    my @names;
    for my $ext (@{$cert->{'tbsCertificate'}{'extensions'}}) {
        if ($ext->{'extnID'} eq $id_ce_subjectAltName) {
            my $l = $subjectAlt_asn->decode($ext->{'extnValue'}) or die $!;
            for my $v (@$l) {
                my $n = $v->{'rfc822Name'};
                push @names, $n if $n;
            }
        }
    }
    return @names;
}

sub sig_mime_caps {
    my ($sig) = @_;
    for my $attr (@{$sig->{'signedAttrs'}}) {
        next if $attr->{'attrType'} ne $id_smimeCapabilities;
        die "invalid SMIMECapabilities attribute" if 1 != @{$attr->{'attrValues'}};
        #openssl_asn1parse($attr->{'attrValues'}[0]);
        my $caps = $smime_caps_asn->decode($attr->{'attrValues'}[0]) or die $!;
        my @caps;
        for my $cap (@$caps) {
            my $name = oid_name($cap->{'capabilityID'}) || $cap->{'capabilityID'};
            if ($cap->{'capabilityID'} eq "1.2.840.113549.3.2") {
                # rc2-cbc has 'parameters' specifying key size
                my $key_size = $int_asn->decode($cap->{'parameters'}) or die $!;
                push @caps, $name . " with " . $key_size . " bits";
            } else {
                push @caps, $name;
            }
        }
        return @caps;
    }
    return ();
}

sub oid_name {
    my ($oid_txt) = @_;

    my $n = Net::SSLeay::OBJ_obj2nid(Net::SSLeay::OBJ_txt2obj($oid_txt, 1));
    return '' unless $n;
    return Net::SSLeay::OBJ_nid2ln($n);
}

sub oid_desc {
    my ($oid_txt) = @_;
    my $oid_name = oid_name($oid_txt);
    $oid_name = "<unknown oid>" unless length $oid_name > 0;
    return $oid_name . " (" . $oid_txt . ")"
}

sub openssl_asn1parse {
    my ($data) = @_;
    pipe my $child_stdin, my $stdin;
    my $h = IPC::Run::start(['openssl', 'asn1parse', '-inform', 'DER', '-i'], '<', $child_stdin);
    close $child_stdin;
    binmode $stdin;
    print $stdin $data;
    close $stdin;
    IPC::Run::finish($h);
}

sub decode_signature {
    my ($signature) = @_;
    my $content = $content_asn->decode($signature) or die $!;
    die "Not a signature" unless $content->{'contentType'} eq $id_signedData;
    #openssl_asn1parse($content->{'content'});
    my $result = $sig_asn->decode($content->{'content'}) or die $!;
    return $result;
}

sub decode_enveloped {
    my ($signature) = @_;
    my $content = $content_asn->decode($signature) or die $!;
    die "Not an encrypted message" unless $content->{'contentType'} eq $id_envelopedData;
    #openssl_asn1parse($content->{'content'});
    my $result = $env_asn->decode($content->{'content'}) or die $!;
    return $result;
}

sub load_file {
    my ($filename) = @_;
    open my $f, '<', $filename or die "Couldn't open file $filename: $!";
    binmode $f;
    my $data = do { local $/; <$f> };
    close $f;
    return $data;
}

sub decode_signature_file {
    my ($signature_file) = @_;
    return decode_signature(load_file($signature_file));
}

sub decode_enveloped_file {
    my ($signature_file) = @_;
    return decode_enveloped(load_file($signature_file));
}

my %name_types = {
    "2.5.4.3" => "CN", # commonName
    "2.5.4.6" => "C", # countryName
    "2.5.4.7" => "L", # localityName
    "2.5.4.8" => "ST", # stateOrProvinceName
    "2.5.4.10" => "O", # organizationName
    "2.5.4.11" => "OU", # organizationalUnitName
};

sub stringify_time {
    my ($time) = @_;
    if ($time->{'utcTime'}) {
        return DateTime->from_epoch(epoch => $time->{'utcTime'})->datetime(q{ })
    } elsif ($time->{'generalTime'}) {
        die "GeneralizedTime not supported yet";
        # Local time only. ``YYYYMMDDHH[MM[SS[.fff]]]'', where the optional fff is accurate to three decimal places.
        # Universal time (UTC time) only. ``YYYYMMDDHH[MM[SS[.fff]]]Z''.
        # Difference between local and UTC times. ``YYYYMMDDHH[MM[SS[.fff]]]+-HHMM''.
    } else {
        die "Invalid time";
    }
}

sub stringify_name {
    my ($name) = @_;
    my @parts;
    for my $entries (@{$name->{'rdnSequence'}}) {
        for my $part (@$entries) {
            my $n = Net::SSLeay::OBJ_obj2nid(Net::SSLeay::OBJ_txt2obj($part->{'type'}, 1));
            $n = $n ? Net::SSLeay::OBJ_nid2sn($n) : $part->{'type'};
            my $outer_value = $part->{'value'};
            my @vkeys = keys %$outer_value;
            die "Invalid value" unless 1 == @vkeys;
            my $v = $outer_value->{$vkeys[0]};
            $v =~ s/([\/\\\x00-\x1f\x7F-\xFF])/ '\\x' . unpack('H2', chr($1)) /gsxe;
            push @parts, "/$n=$v";
        }
    }
    return (join '', @parts);
}

sub stringify_name_legacy {
    my ($name) = @_;
    my $first = 1;
    my @parts;
    for my $entries (@{$name->{'rdnSequence'}}) {
        my @entries = ();
        for my $part (@$entries) {
            my $n = Net::SSLeay::OBJ_obj2nid(Net::SSLeay::OBJ_txt2obj($part->{'type'}, 1));
            $n = $n ? Net::SSLeay::OBJ_nid2sn($n) : $part->{'type'};
            my $outer_value = $part->{'value'};
            my @vkeys = keys %$outer_value;
            die "Invalid value" unless 1 == @vkeys;
            my $v = $outer_value->{$vkeys[0]};
            $v =~ s/([\/\\\x00-\x1f\x7F-\xFF])/ '\\x' . unpack('H2', chr($1)) /gsxe;
            if ($first) {
                push @parts, "$n=$v";
            } elsif ($n =~ m/^[A-Z]{1,2}$/) {
                push @parts, ", $n=$v";
            } else {
                push @parts, "/$n=$v";
            }
            $first = 0;
        }
    }
    return (join '', @parts);
}

1;

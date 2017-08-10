#!/usr/bin/env perl

use strict;

use Data::Dumper;
use File::Temp;
use IPC::Open3;
use IPC::Run;
use MIME::Decoder;
use MIME::Entity;
use MIME::Parser;

use lib '.';
use SMimeAsn1;

open(DEVNULL,'+>', '/dev/null') or die "open /dev/null failed";

my $tmpdir = File::Temp->newdir();

sub decode_entity {
	my ($entity) = @_;
	if ($entity->bodyhandle->is_encoded) {
		my $message = File::Temp->new();
		open my $MSG, '>', $message->filename;
		$entity->print($MSG);
		close($MSG);

		my $parser = new MIME::Parser;
		$parser->tmp_dir($tmpdir->dirname);
		$parser->output_under($tmpdir->dirname);

		return $parser->parse_open($message->filename);
	} else {
		return $entity;
	}
}

sub gpgsm {
	IPC::Run::run(['gpgsm', @_], '<', \*DEVNULL, '>', \*DEVNULL, '2>', \*DEVNULL);
	#die "gpgsm failed with status: ${^CHILD_ERROR_NATIVE}" if ${^CHILD_ERROR_NATIVE};
}

sub gpgsm_get_stdout {
	pipe my $stdout, my $child_stdout;
	my $h = IPC::Run::start(['gpgsm', @_], '<', \*DEVNULL, '>', $child_stdout);
	close $child_stdout;

	local $/ = undef;
	my $stdout_data = <$stdout>;

	IPC::Run::finish($h);

	return $stdout_data;

	die "gpgsm failed with status: ${^CHILD_ERROR_NATIVE}" if ${^CHILD_ERROR_NATIVE};
}

sub gpgsm_get_stderr {
	pipe my $stderr, my $child_stderr;
	my $h = IPC::Run::start(['gpgsm', @_], '<', \*DEVNULL, '2>', $child_stderr);
	close $child_stderr;

	local $/ = undef;
	my $stderr_data = <$stderr>;

	IPC::Run::finish($h);

	return $stderr_data;

	die "gpgsm failed with status: ${^CHILD_ERROR_NATIVE}" if ${^CHILD_ERROR_NATIVE};
}

my $PARSE_PKCS7_BINARY_DATA = 0;
sub openssl_pkcs7_structure {
	pipe my $stdout, my $child_stdout;
	my $h = IPC::Run::start(['openssl', 'pkcs7', '-print', '-noout', @_], '<', \*DEVNULL, '>', $child_stdout, '2>', \*DEVNULL);
	close $child_stdout;

	my $line = <$stdout>; # ignore first line "pkcs7: PKCS7:"
	my @indents = ();
	my $data = {};
	while (<$stdout>) {
		#print "parsing: $_";
		if ($_ =~ m/^$/) {
			# skip empty line
		} elsif ($_ =~ m/^ *(OCTET STRING:$|[0-9]+:d=|\(unknown\))/) {
			# skip
		} elsif ($_ =~ m/^( *)([a-zA-Z._\-0-9]+):(?: ?(.*))?$/) {
			my $indent = length $1;
			my $level = $#indents;
			while ($level > 0 && $indents[$level][0] >= $indent) {
				pop @indents;
				$level--;
			}
			my $current_hash;
			if ($level > 0) {
				my $lvl_data = $indents[$level][1];
				my $lvl_key = $indents[$level][2];
				unless (defined $lvl_data->{$lvl_key}) {
					$lvl_data->{$lvl_key} = {};
				}
				$current_hash = $lvl_data->{$lvl_key};
			} else {
				$current_hash = $data;
			}
			my $key = $2;
			my $value = $3;
			if (defined $value && length $value > 0) {
				$current_hash->{$key} = $value;
			}
			push @indents, [$indent, $current_hash, $key];
		} elsif ($_ =~ m/^( *)([a-fA-F0-9]+) - ((?:[a-fA-F0-9]{2}[ \-])*)/) {
			my $indent = length $1;
			my $offset = $2;
			my $value = $3;

			my $level = $#indents;
			while ($level > 0 && $indents[$level][0] >= $indent) {
				pop @indents;
				$level--;
			}
			my $lvl = $indents[$level];
			my $lvl_data = $lvl->[1];
			my $lvl_key = $lvl->[2];
			if ((not defined $lvl_data->{$lvl_key}) || ($lvl_data->{$lvl_key} =~ m/:$/ && not defined $lvl->[3])) {
				$lvl->[3] = 'binary data';
				$lvl_data->{$lvl_key} = '';
			}
			if ($PARSE_PKCS7_BINARY_DATA) {
				$value =~ s/-/ /;
				$lvl_data->{$lvl_key} .= join "", map(chr, map { hex } split / /, $value);
			} else {
				$lvl_data->{$lvl_key} = '<binary data>';
			}
		} elsif ($_ =~ m/^( *)<EMPTY>/) {
			my $indent = length $1;
			my $offset = $2;
			my $value = $3;

			my $level = $#indents;
			while ($level > 0 && $indents[$level][0] >= $indent) {
				pop @indents;
				$level--;
			}
			my $lvl = $indents[$level];
			my $lvl_data = $lvl->[1];
			my $lvl_key = $lvl->[2];
			if ((not defined $lvl_data->{$lvl_key}) || ($lvl_data->{$lvl_key} =~ m/:$/ && not defined $lvl->[3])) {
				$lvl->[3] = 'binary data';
				$lvl_data->{$lvl_key} = '';
			}
			if (not $PARSE_PKCS7_BINARY_DATA) {
				$lvl_data->{$lvl_key} = '<empty binary data>';
			}
		} else {
			die "Unparseable line: $_";
		}
	}

	IPC::Run::finish($h);

	die "openssl failed with status: ${^CHILD_ERROR_NATIVE}" if ${^CHILD_ERROR_NATIVE};

	return $data;
}

# MIME::Parser modifies the parts; for signatures we need them as-is.
sub split_mime_parts {
	my ($filename, $boundary) = @_;
	my $part = 0;
	open my $in_file, '<', $filename or die $!;
	my $out_file;
	# need to chop \r\n from last line before boundary
	my $prev_line;

	my @part_filenames;

	for my $line (<$in_file>) {
		my $line_content = $line;
		$line_content =~ s/\s*\z//;
		if ($line_content eq "--${boundary}") {
			$prev_line =~ s/\r?\n\z//;
			print $out_file $prev_line if defined $out_file;
			close $out_file if defined $out_file;

			$part++;
			push @part_filenames, $filename.'.'.$part;
			open $out_file, '>', $filename.'.'.$part or die $!;
		} elsif ($line_content eq "--${boundary}--") {
			$prev_line =~ s/\r?\n\z//;
			print $out_file $prev_line if defined $out_file;
			close $out_file if defined $out_file;

			return @part_filenames;
		} else {
			print $out_file $prev_line if defined $out_file;
			$prev_line = $line;
		}
	}
	die "Missing terminating boundary";
}

my $parser = new MIME::Parser;
$parser->tmp_dir($tmpdir->dirname);
$parser->output_under($tmpdir->dirname);
#$parser->decode_headers(1);
$parser->decode_bodies(0);

my $entity_file = $tmpdir->dirname . '/' . 'input';
system("cat > $entity_file");
my $entity = $parser->parse_open($entity_file);

# $entity->dump_skeleton;

if ($entity->head->mime_attr('Content-Type.smime-type') eq "enveloped-data") {
	$entity = decode_entity($entity);
	my $encfile = $entity->bodyhandle->path;
	# encrypted
	gpgsm('--quiet', '--decrypt', '-o', $encfile . ".decrypted", $encfile);
	$entity_file = $entity->bodyhandle->path . ".decrypted";
	$entity = $parser->parse_open($entity_file);
	# $entity->dump_skeleton;

	#my $ssl_data = openssl_pkcs7_structure('-inform', 'DER', '-in', $encfile);
	#system('openssl', 'asn1parse', '-inform', 'DER', '-in', $encfile, '-i');
	my $data = SMimeAsn1::decode_enveloped_file($encfile);
	#print Dumper($data);

	print "-- Encrypted message --\n";
	for my $r (@{$data->{'recipientInfos'}}) {
		print "Recipient:\n";
		print "  Issuer: ", SMimeAsn1::stringify_name_legacy($r->{'ktri'}{'rid'}{'issuerAndSerialNumber'}{'issuer'}), "\n";
		print "  Serial: ", $r->{'ktri'}{'rid'}{'issuerAndSerialNumber'}{'serialNumber'}, "\n";
		print "  Key encryption algorithm: ", SMimeAsn1::oid_desc($r->{'ktri'}{'keyEncryptionAlgorithm'}{'algorithm'}), "\n";
	}
	print "Data encryption algorithm: ", SMimeAsn1::oid_desc($data->{'encryptedContentInfo'}{'contentEncryptionAlgorithm'}{'algorithm'}), "\n";
	#print "Recipient certificate:\n";
	#print "  Issuer: ", $ssl_data->{'d.enveloped'}{'recipientinfo'}{'issuer_and_serial'}{'issuer'}, "\n";
	#print "  Serial: ", $ssl_data->{'d.enveloped'}{'recipientinfo'}{'issuer_and_serial'}{'serial'}, "\n";
	#print "Key encryption algorithm: ", $ssl_data->{'d.enveloped'}{'recipientinfo'}{'key_enc_algor'}{'algorithm'}, "\n";
	#print "Data encryption algorithm: ", $ssl_data->{'d.enveloped'}{'enc_data'}{'algorithm'}{'algorithm'}, "\n";
	print "\n";
}

my $body = $entity;
my $sig;
my $verify_msg;
my $sigtype;

if ($entity->head->mime_attr('Content-Type.smime-type') eq "signed-data") {
	$sigtype = "non-detached";
	$sig = decode_entity($entity);
	my $sigfile = $sig->bodyhandle->path;
	$verify_msg = gpgsm_get_stderr('--verify', '--quiet', '--disable-policy-checks', '-o', $sigfile . ".content", $sigfile);
	$body = $parser->parse_open($sigfile . ".content");
} elsif ($entity->head->mime_attr('Content-Type') eq 'multipart/signed' and $entity->head->mime_attr('Content-Type.protocol') =~ '^application/(?:x-)?pkcs7-signature$') {
	$sigtype = "detached";

	my @parts = split_mime_parts($entity_file, $entity->head->mime_attr('Content-Type.boundary'));
	die "Expected 2 parts in multipart/signed" unless 2 == scalar(@parts);
	my $body_file = $parts[0];
	$body = $parser->parse_open($body_file);
	$sig = decode_entity($parser->parse_open($parts[1]));
	die "Expected pkcs7-signature as second part" unless $sig->head->mime_attr('Content-Type') =~ m#application/(x-)?pkcs7-signature#;

	my $sigfile = $sig->bodyhandle->path;

	# make sure it really uses CRLF
	system('sed', '-i', '-e', 's/\r\?$/\r/', $body_file);

	$verify_msg = gpgsm_get_stderr('--verify', '--quiet', '--disable-policy-checks', $sigfile, $body_file);
}

if ($sig) {
	my $data = SMimeAsn1::decode_signature_file($sig->bodyhandle->path);
	#print Dumper($data);
	#my $ssl_data = openssl_pkcs7_structure('-inform', 'DER', '-in', $sig->bodyhandle->path);

	my %known_certs;
	print "-- Signed message ($sigtype signature) --\n";
	print "Contained certificates: \n";
	for my $cert (@{$data->{'certificates'}}) {
		$cert = $cert->{'certificate'};
		next unless $cert; # skip other formats
		my $issuer = SMimeAsn1::stringify_name_legacy($cert->{'tbsCertificate'}{'issuer'});
		my $serial = $cert->{'tbsCertificate'}{'serialNumber'};
		my $pubkey = $cert->{'tbsCertificate'}{'subjectPublicKeyInfo'};
		my @mail_names = SMimeAsn1::subject_alt_rfc822names($cert);
		print "- Subject: ", SMimeAsn1::stringify_name_legacy($cert->{'tbsCertificate'}{'subject'}), "\n";
		print "  Alternative Mail Names: ", (join ', ', @mail_names), "\n" if @mail_names;
		print "  Issuer: ", $issuer, "\n";
		print "  Serial: ", $serial, " (", sprintf("0x%X", $serial), ")\n";
		print "  Key: ", SMimeAsn1::oid_desc($pubkey->{'algorithm'}->{'algorithm'}), "\n";
		print "  Signature algorithm: ", SMimeAsn1::oid_desc($cert->{'tbsCertificate'}{'signature'}{'algorithm'}), "\n";
		print "  Not Before: ", SMimeAsn1::stringify_time($cert->{'tbsCertificate'}{'validity'}{'notBefore'}), "\n";
		print "  Not After: ", SMimeAsn1::stringify_time($cert->{'tbsCertificate'}{'validity'}{'notAfter'}), "\n";
		$known_certs{$issuer . '///' . $serial} = $cert;
	}

	print "Digest algorithms:\n";
	for my $alg (@{$data->{'digestAlgorithms'}}) {
		print "- ", SMimeAsn1::oid_desc($alg->{'algorithm'}), "\n";
	}

	print "Signatures:\n";
	for my $sig (@{$data->{'signerInfos'}}) {
		# $sig->{'signedAttrs'}
		my $issuer = SMimeAsn1::stringify_name_legacy($sig->{'sid'}{'issuerAndSerialNumber'}{'issuer'});
		my $serial = $sig->{'sid'}{'issuerAndSerialNumber'}{'serialNumber'};
		my $cert = $known_certs{$issuer . '///' . $serial};
		if ($cert) {
			my @mail_names = SMimeAsn1::subject_alt_rfc822names($cert);
			print "- By: ", SMimeAsn1::stringify_name_legacy($cert->{'tbsCertificate'}{'subject'}), "\n";
			print "  (", (join ', ', @mail_names), ")\n" if @mail_names;
		} else {
			print "- By unknown cert from:\n";
			print "  Issuer: ", $issuer, "\n";
			print "  Serial: ", $serial, " (", sprintf("0x%X", $serial), ")\n";
		}
		print "  Digest algorithm: ", SMimeAsn1::oid_desc($sig->{'digestAlgorithm'}{'algorithm'}), "\n";
		print "  Signature algorithm: ", SMimeAsn1::oid_desc($sig->{'signatureAlgorithm'}{'algorithm'}), "\n";
		print "  Client SMIMECapabilities: ", (join ', ', SMimeAsn1::sig_mime_caps($sig)), "\n";
	}

	#print "Digest algorithm: ", SMimeAsn1::oid_desc($data->{'signerInfos'}[0]{'digestAlgorithm'}{'algorithm'}), "\n";
	#print "Signature algorithm: ", SMimeAsn1::oid_desc($data->{'signerInfos'}[0]{'signatureAlgorithm'}{'algorithm'}), "\n";
	#print "Signature algorithm: ", $ssl_data->{'d.sign'}{'md_algs'}{'algorithm'}, "\n";
	print "Content-Type: ", $sig->head->get("Content-Type"), "\n";
	print $verify_msg;
	print "\n";
}

print "--\n";
if ($body->parts || $body->effective_type !~ m#^text/#) {
	# print full body with headers
	$body->print(\*STDOUT);
} else {
	# decode text body, remove transfer encoding
	$body = decode_entity($body);
	$body->head->delete('Content-Transfer-Encoding');
	$body->head->print(\*STDOUT);
	print "\n";
	$body->bodyhandle->print(\*STDOUT);
}

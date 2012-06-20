#!/usr/bin/perl
# CuckooMX.pl
# Content-filter for the Postfix MTA which submit attached documents to a
# Cuckoo instance for automatic analysis.
#
# Copyright (C) 2012 Xavier Mertens <xavier(at)rootshell(dot)be>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 3. Neither the name of copyright holders nor the names of its
# contributors may be used to endorse or promote products derived
# from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# History
# -------
# 2012/06/20	First release
#

use Archive::Extract;
# use Archive::Rar;
use DBI;
use Digest::MD5;
use File::Path qw(make_path remove_tree);
use MIME::Parser;
use Sys::Syslog;
use XML::XPath;
use XML::XPath::XMLParser;
use strict;
use warnings;

# Postfix must receive one of the following code in case
# of problems. We do NOT use die() here!
use constant EX_TEMPFAIL	=> 75;  # Mail sent to the deferred queue (retry)
use constant EX_UNAVAILABLE	=> 69;	# Mail bounced to the sender (undeliverable)

# ----------------------------------------------------------
# Default Configuration (to be configured via cuckoomx.conf)
# ----------------------------------------------------------
my $syslogProgram	= "cuckoomx";
my $configFile		= "/data/cuckoo/conf/cuckoomx.conf";
my $sendmailPath	= "/usr/sbin/sendmail";
my $syslogFacility	= "mail";
my $cuckooDB		= "/data/cuckoo/db/cuckoo.db";
my $cuckooDir		= "/data/cuckoo";
my $cuckooVM		= "Cuckoo1";
my $outputDir		= "/data/cuckoo/quarantine"; # Temporary directory based on our PID
my $notifyEmail		= "xavier\@example.com";
my $processZip		= 1;
my $processRar		= 1;

# Define the file types to ignore
# By default, we don't care about plain text, HTML files and images.
my @suspiciousFiles;
my @ignoreTypes;

# Read running parameters
if (!readConfigFile($configFile)) {
	syslogOutput("Cannot load configuration from $configFile");
	exit EX_TEMPFAIL;
}

# Create our working directory
$outputDir = $outputDir . '/' . $$;
if (! -d $outputDir && !make_path("$outputDir", { mode => 0700 })) {
	syslogOutput("mkdir($outputDir) failed: $!");
	exit EX_TEMPFAIL;
}

# Save the mail from STDIN
if (!open(OUT, ">$outputDir/content.tmp")) {
	syslogOutput("Write to \"$outputDir/content.tmp\" failed: $!");
	exit EX_TEMPFAIL;
}
while(<STDIN>) {
	print OUT $_;
}
close(OUT);

# Save the sender & recipients passed by Postfix
if (!open(OUT, ">$outputDir/args.tmp")) {
	syslogOutput("Write to \"$outputDir/args.tmp\" failed: $!");
	exit EX_TEMPFAIL;
}
foreach my $arg (@ARGV) {
	print OUT $arg . " ";
}
close(OUT);

# Extract MIME types from the message
my $parser = new MIME::Parser;
$parser->output_dir($outputDir);
my $entity = $parser->parse_open("$outputDir/content.tmp");

# Extract sender and recipient(s)
my $headers = $entity->head;
my $from = $headers->get('From');
my $subject = $headers->get('Subject');
chomp($from);
chomp($subject);

syslogOutput("Processing mail from: $from ($subject)");
# Recursively process the MIME entities
processMIMEParts($entity);
if (! @suspiciousFiles) {
	# No MIME data extracted, send the (safe) mail immediately
	deliverMail();
	# We can safely remove the mail from the quarantine
	remove_tree($outputDir) or syslogOuput("Cannot delete \"$outputDir\": $!");
	exit 0;
} 
else {
	syslogOutput("Files to process: " . @suspiciousFiles);
		
	# Connect to the Cuckoo DB
	my $dbh = DBI->connect("dbi:SQLite:dbname=$cuckooDB");
	if (!$dbh) {
		syslogOutput("Connect to Cuckoo DB failed: " . $DBI::errstr);
		exit EX_TEMPFAIL;
	}

	for my $file (@suspiciousFiles) {
		# Compute MD5 hash
		if (!open(FILE, "$file")) {
			syslogOutput("Open \"$file\" failed: $!");
			exit EX_TEMPFAIL;
		}
		binmode(FILE);
		my $md5Digest = Digest::MD5->new->addfile(*FILE)->hexdigest;
		close(FILE);
		
		# Search for existing MD5 in the Cuckoo DB
		# to skip already submitted files
		my $row = $dbh->selectrow_arrayref("SELECT md5 FROM queue where md5=\"$md5Digest\"");
	
		if (!$row) {
			# MD5 not found, process the new file!
			$dbh->do("INSERT INTO queue \
				(target, md5, timeout, package, priority, custom, vm_id) \
				VALUES (\"$file\", \"$md5Digest\", NULL, NULL, NULL, \
				NULL, \"$cuckooVM\")");
			if ($DBI::errstr) {
				syslogOutput("Cannot submit file: " . $DBI::errstr);
				exit EX_TEMPFAIL;
			}
		}
		else {
			syslogOutput("\"$file\" already scanned (MD5: $md5Digest)");
		}
	}
	$dbh->disconnect;
	# Now, mail is always delivered
	# Todo: Quarantine system + notify admin
	deliverMail();
}
exit 0;

#
# processMIMEParts
# 

sub processMIMEParts
{
	my $entity = shift || return;
	for my $part ($entity->parts) {
		if($part->mime_type eq 'multipart/alternative' ||
		   $part->mime_type eq 'multipart/related' ||
		   $part->mime_type eq 'multipart/mixed' ||
		   $part->mime_type eq 'multipart/signed' ||
		   $part->mime_type eq 'message/rfc822' ) {
			# Recursively process the message
			processMIMEParts($part);
		}
		else {
			my $type = lc  $part->mime_type;
			my $bh = $part->bodyhandle;
			syslogOutput("Dumped: \"" . $bh->{MB_Path} . "\" (" . $type . ")");
			# Ignore our trusted MIME-types
			if (!grep {$_ eq $type} @ignoreTypes) {
				# Uncompress ZIP archives
				if ($type eq "application/zip" && $processZip) { 
					my $ae = Archive::Extract->new( archive => $bh->{MB_Path});
					my $zip = $ae->extract(to => $outputDir);
					if (!$zip) {
						syslogOutput("Cannot extract files from \"" . $bh->{MB_Path} . "\": $!");
						exit EX_TEMPFAIL; 
					}
					foreach my $f ($ae->files) {
						push(@suspiciousFiles, $outputDir . "/" . $f->[0]);
					}
				}
				# *** TODO ***
				# elsif ($type eq "application/x-rar" && $processRar)) {
				# 	my $rar = new Archive::Rar();
				# 	$rar->Extract(-archive => $bh->{MB_Path}
				# }
				# else {
				else {
					push(@suspiciousFiles, $bh->{MB_Path});
				}
			}
		}
	}
	return;
}

#
# deliverMail - Send the mail back
#
sub deliverMail {
	# Read saved arguments
	if (! open(IN, "<$outputDir/args.tmp")) {
		syslogOutput("deliverMail: Cannot read $outputDir/args.tmp: $!");
		exit EX_UNAVAILABLE;
	}
	my $sendmailArgs = <IN>;
	close(IN);
	
	# Read mail content
	if (! open(IN, "<$outputDir/content.tmp")) {
		syslogOutput("deliverMail: Cannot read $outputDir/content.txt: $!");
		exit EX_UNAVAILABLE;
	}
	
	# Spawn a sendmail process
	syslogOutput("Spawn=$sendmailPath -G -i $sendmailArgs");
	if (! open(SENDMAIL, "|$sendmailPath -G -i $sendmailArgs")) {
		syslogOutput("deliverMail: Cannot spawn: $sendmailPath $sendmailArgs: $!");
		exit EX_TEMPFAIL;
	}
	while(<IN>) {
		print SENDMAIL $_;
	}
	close(IN);
	close(SENDMAIL);
}

#
# Send Syslog message using the defined facility
#
sub syslogOutput {
        my $msg = shift or return(0);
	openlog($syslogProgram, 'pid', $syslogFacility);
	syslog('info', '%s', $msg);
	closelog();
}

# 
# Load & validate the configuration from provided XML file
#
sub readConfigFile {
        my $configFile = shift || return 0;
	my $xml = XML::XPath->new(filename => "$configFile");
	my $buff;
	
	# Core Parameters
	my $nodes = $xml->find('/cuckoomx/core');
	foreach my $node ($nodes->get_nodelist) {
		$buff		= $node->find('process-zip')->string_value;
		(lc($buff) eq "yes" || $buff eq "1") && $processZip++;
		$buff           = $node->find('process-rar')->string_value;
		(lc($buff) eq "yes" || $buff eq "1") && $processRar++;
		$outputDir	= $node->find('outputdir')->string_value;
	}

	# Cuckoo Parameters
	$nodes = $xml->find('/cuckoomx/cuckoo');
	foreach my $node ($nodes->get_nodelist) {
		$cuckooDir	= $node->find('basedir')->string_value;
		$cuckooDB	= $node->find('db')->string_value;
		$cuckooVM	= $node->find('guest')->string_value;
	}

	# Logging Parameters
	$nodes = $xml->find('/cuckoomx/logging');
	foreach my $node ($nodes->get_nodelist) {
		$syslogFacility	= $node->find('syslogfacility')->string_value;
		$sendmailPath	= $node->find('sendmailpath')->string_value;
		$notifyEmail	= $node->find('notify')->string_value;
	}

	# Ignore MIME-types
	$nodes = $xml->find('/cuckoomx/ignore/mime-type/text()');
	foreach my $node ($nodes->get_nodelist) {
		$buff = $node->string_value;
		push(@ignoreTypes, $buff);
	}
	return 1;
}


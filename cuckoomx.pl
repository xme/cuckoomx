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
# 2012/07/03	Added processing of URLs inside the body
# 2012/07/04	Added libmagic support for better detection of files
#

use Archive::Extract;
# use Archive::Rar;
use DBI;
use Digest::MD5;
use File::LibMagic;
use File::Path qw(make_path remove_tree);
use File::Temp;
use MIME::Parser;
use Sys::Syslog;
use URI::Find;
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
my $processUrl		= 0;

# Define the file types to ignore
# By default, we don't care about plain text, HTML files and images.
my @suspiciousFiles;
my @suspiciousURLs;
my @ignoreMimes;
my @ignoreURLs;

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

# Step 1 : Extract URLs from content (optional)
($processUrl) && processURLs("$outputDir/content.tmp");

# Step 2 : Recursively process the MIME entities
processMIMEParts($entity);

if (! @suspiciousFiles && ! @suspiciousURLs) {
	# No MIME data extracted, send the (safe) mail immediately
	deliverMail();
	# We can safely remove the mail from the quarantine
	remove_tree($outputDir) or syslogOuput("Cannot delete \"$outputDir\": $!");
	exit 0;
} 
else {
	# Connect to the Cuckoo DB
	my $dbh = DBI->connect("dbi:SQLite:dbname=$cuckooDB");
	if (!$dbh) {
		syslogOutput("Connect to Cuckoo DB failed: " . $DBI::errstr);
		exit EX_TEMPFAIL;
	}

	# Submit suspicious files to Cuckoo
	syslogOutput("Files to process: " . @suspiciousFiles);
	for my $f (@suspiciousFiles) {
		submitFile($f, $dbh);
	}

	# Submit suspicious URLs to Cuckoo (optional)
	if ($processUrl) {
		syslogOutput("URLs to process: " . @suspiciousURLs);	
		foreach my $u (@suspiciousURLs) {
			submitURL($u, $dbh);
		}
	}

	$dbh->disconnect;

	# Now, mail is always delivered
	# Todo: Quarantine system + notify admin
	deliverMail();
}
exit 0;

#
# getPackage	Use File::LigMagic to guess the file type
#		and return the right analysis package
#
# Input:	$f - Path of file to analyze
# Output:	Package name or empty string if not supported
#
sub getPackage {
	my $f = shift || return("");
	my $flm = File::LibMagic->new();
	my $b = $flm->describe_filename("$f");
	if ( $b =~ /Microsoft [Office ]*PowerPoint/i ) {
		return("ppt");
	}
	elsif ( $b =~ /Microsoft [Office ]*Excel/i ) {
		return("xls");
	}
	elsif ($b =~ /Microsoft [Office ]*Word/i ||
	    $b =~ /Composite Document File V\d Document/i	 ||
	    $b =~ /Rich Text Format/i) {
		return("doc");
	}
	elsif ( $b =~ /PDF Document/i) {
		return("pdf");
	}
	elsif ( $b =~ /HTML document/i) {
		return("firefox");
	}
	elsif ( $b =~ /PHP script/i) {
		return("php");
	}
	elsif ( $b =~ /diff output/i) {
		return("");
	}
	else {
		# Default package
		return("exe");
	}
}

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
		   $part->mime_type eq 'multipart/report' ||
		   $part->mime_type eq 'message/rfc822' ) {
			# Recursively process the message
			processMIMEParts($part);
		}
		else {
			my $type = lc  $part->mime_type;
			my $bh = $part->bodyhandle;
			syslogOutput("Dumped: \"" . $bh->{MB_Path} . "\" (" . $type . ")");
			# Ignore our trusted MIME-types
			if (!grep {$_ eq $type} @ignoreMimes) {
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
# processURLs
#
sub processURLs {
	my $content = shift || return;
	syslogOutput("DEBUG: processURLs($content)");
	my $buffer;
	if (! open(IN, "<$content")) {
		syslogOutput("processURLs: Cannot read $content: $!");
		exit EX_UNAVAILABLE;
	}
	while(<IN>) { $buffer = $buffer . $_; }
	close(IN);

	# Reformat text 
	$buffer =~ s/=\n//g;    # Remove trailing "="

	my $finder = URI::Find->new(
			sub {
				my $u = shift;
				my $matchExclude = 0;
				if ($u =~ /^http[s]*:\/\//) { # Process only HTTP(S) URI
					if (!($u =~ /\.(jpg|jpeg|png|gif)$/i)) { # Ignore common pictures & files
						foreach my $iu (@ignoreURLs) {
							($u =~ /$iu/i) && $matchExclude++;
						}
						if (!$matchExclude && 
						    !(grep /$u/, @suspiciousURLs)) {
							# URLs not excluded and not already found -> save it
							push(@suspiciousURLs, $u);
						}
						#else {
						#	syslogOutput("DEBUG: Exclude: $u");
						#}
					}
				}
				#else {
				#	syslogOutput("DEBUG: Ignoring URI: $u");
				#}
			}
		     );
	$finder->find(\$buffer);
	return; 
}

#
# submitFile
#
sub submitFile {
	my $file = shift || return;
	my $dbh  = shift || return;

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
	my $row = $dbh->selectrow_arrayref("SELECT md5 FROM tasks where md5=\"$md5Digest\"");

	if (!$row) { # MD5 not found, process the new file!
		# Try to detect the file type to use the right analysis package
		my $package = getPackage($file);
		if ($package) { # Got a valid package, submit the file
			$dbh->do("INSERT INTO tasks \
				(file_path, md5, timeout, package, priority, custom, machine) \
				VALUES (\"$file\", \"$md5Digest\", NULL, \"$package\", NULL, \
				NULL, \"$cuckooVM\")");
			if ($DBI::errstr) {
				syslogOutput("Cannot submit file: " . $DBI::errstr);
				exit EX_TEMPFAIL;
			}
		}
	}
	else {
		syslogOutput("\"$file\" already scanned (MD5: $md5Digest)");
	}
}

#
# submitURL
#
sub submitURL {
	my $url = shift || return;
	my $dbh = shift || return;

	my $buffer = "[InternetShortcut]\r\nURL=$url\r\n";
	# Generate the MD5 hash and search the database to avoid
	# duplicate URLs
	my $md5Digest  = Digest::MD5->new->add($buffer)->hexdigest;
	my $row = $dbh->selectrow_arrayref("SELECT md5 FROM tasks where md5=\"$md5Digest\"");
	if (!$row) { # MD5 not found, submit the URL
		$url =~ /http[s]*:\/\/((\w|\.)+)/;
		my $prefix = $1;
		$prefix =~ tr/\./\-/;
		my $tmpFile = File::Temp->new( TEMPLATE => $prefix .'_XXXXXXXXXXXXXXXX',
					       DIR => "$outputDir",
					       SUFFIX => '.url',
					       UNLINK => '0' );
		syslogOutput("DEBUG: Creating tempfile $tmpFile");
		if (!open(TF, ">$tmpFile")) {
			syslogOutput("Cannot create file $tmpFile: $!");
			exit EX_TEMPFAIL;
		}
		print TF $buffer;
		close(TF);

		syslogOutput("DEBUG: Submit URL: \"$url\"");
		#$dbh->do("INSERT INTO tasks \
		#	(file_path, md5, timeout, package, priority, custom, machine) \
		#	VALUES (\"$tmpFile\", \"$md5Digest\", NULL, \"firefox\", NULL, \
		#	NULL, \"$cuckooVM\")");
		if ($DBI::errstr) {
			syslogOutput("Cannot submit URL: " . $DBI::errstr);
			exit EX_TEMPFAIL;
		}
	}
	else {
		syslogOutput("\"$url\" already submitted (MD5: $md5Digest)");
	}
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
		$buff           = $node->find('process-url')->string_value;
		(lc($buff) eq "yes" || $buff eq "1") && $processUrl++;
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
	$nodes = $xml->find('/cuckoomx/ignore-mime/mime-type/text()');
	foreach my $node ($nodes->get_nodelist) {
		$buff = $node->string_value;
		push(@ignoreMimes, $buff);
	}

	# Ignore URLs
	$nodes = $xml->find('/cuckoomx/ignore-url/url/text()');
	foreach my $url ($nodes->get_nodelist) {
		$buff = $url->string_value;
		push(@ignoreURLs, $buff);
	}
	return 1;
}

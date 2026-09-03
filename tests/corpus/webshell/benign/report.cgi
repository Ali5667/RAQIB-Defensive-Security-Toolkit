#!/usr/bin/perl
use CGI;
my $q = CGI->new;
print $q->header('text/plain');
print "Report generated at " . localtime() . "\n";

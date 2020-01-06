#!/usr/bin/perl -wT

use strict;
use CGI qw(:standard);
use CGI::Carp qw(warningsToBrowser fatalsToBrowser);

print header;
print start_html("Environment");

print "<pre>";
foreach my $key (sort(keys(%ENV))) {
    print "$key = $ENV{$key}<br>";
}
print "</pre>";

print end_html;

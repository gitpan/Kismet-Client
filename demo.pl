#!/usr/bin/perl -I../../
use Kismet::Client;

# Simple demo - Kismet:Client
#
# Freeware or whatever. Do whatever you please with this,
# just dont blame me.
#

my $kismet = Kismet::Client->new(server => '127.0.0.1', port => 2501);

$kismet->add_handler('NETWORK', \&network);

$kismet->connect();

$kismet->enable("NETWORK", '*');

sub network {
   my %info = @_;
   print "SSID:$info{ssid} WEP:$info{wep} BSSID:$info{bssid}\n";
}

$kismet->run();

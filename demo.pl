#!/usr/bin/perl
use Kismet::Client;

# Simple demo of Kismet:Client
#
# Freeware or whatever. Do whatever you whant with this,
# just dont blame me.
#

my $kismet = Kismet::Client->new(server => '127.0.0.1', port => 2501);
$kismet->connect();

$kismet->enable("NETWORK", '*');
$kismet->add_handler('NETWORK', \&network);

sub network {
   my %info = @_;
   print "SSID:$info{ssid} WEP:$info{wep} BSSID:$info{bssid}\n";
}

$kismet->run();

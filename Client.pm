package Kismet::Client;

use 5.006;
use strict;
use warnings;
use Carp;
use POSIX;
use IO::Select;
use IO::Socket;
use Socket;
use Fcntl;

our $VERSION = '0.03';

=head1 NAME

Kismet::Client - Object-oriented module to connect to a Kismet server

=head1 DESCRIPTION

This is an object-oriented module to connect to a Kismet server created
by Mike Kershaw <dragorn@kismetwireless.net>

=head1 AUTHOR

Kay Sindre Bærulfsen <kaysb @ uten.net>

=head1 WHAT IS KISMET

Kismet is a 802.11 wireless network sniffer - this is different
from a normal network sniffer (such as Ethereal or tcpdump)
because it separates and identifies different wireless networks in
the area. Kismet works with any 802.11b wireless card which is
capable of reporting raw packets (rfmon support), which include
any prism2 based card (Linksys, D-Link, Rangelan, etc), Cisco
Aironet cards, and Orinoco based cards. Kismet also supports the
WSP100 remote sensor by Network Chemistry, and is able to sniff
802.11a networks using ar5k cards.

=head1 METHOD REFERENCE

=head2 new

   $kismet = Kismet::Client->new(server => '127.0.0.1',
			         port   => 2501);
				 
The constructor new take two parameters; 'server', 'port'

=cut
							      
sub new {
   my $class = shift;
   my $self;

   my %args = @_;

   croak ("Need a server host/addr") unless($self->{'_SERVER'}=$args{'server'});
   croak ("Need a server port") unless($self->{'_PORT'}=$args{'port'});
   
   $self->{'_CONNECTED'} = 0;
   bless ($self, $class);
   return $self;
}

=head2 connected

   $kismet->connected

Returns the connection state.

=cut

sub connected { return $_[0]->{'_CONNECTED'}; }

=head2 connect

   $kismet->connect();
   
Take no parameters. This function will make a connection to
the Kismet-server. Will carp on fail.

=cut

sub connect {
   my $self = shift;
   
   $self->{'_SOCKET'} = IO::Socket::INET->new(	   PeerPort => $self->{'_PORT'},
					   PeerAddr => $self->{'_SERVER'},
					   Proto    => 'tcp')
				                   or croak "Cant connect to $self->{'_SERVER'}:$self->{'_PORT'} ($@)\n";

   $self->{'_SELECT'}=IO::Select->new($self->{'_SOCKET'});

   my $flags = fcntl($self->{'_SOCKET'}, F_GETFL, 0) or croak "Can't get flag... $!\n";
																	        
   fcntl($self->{'_SOCKET'}, F_SETFL, $flags | O_NONBLOCK) or croak "Can't make socket nonblocking: $!\n";

   $self->{'_CONNECTED'} = 1;

   $self->_read foreach (1..50);
}

=head2 run

   $kismet->run(0.25);

Starts a mainloop. The module will not return from this function.
run takes one parameter, the delay between the loops in seconds.

=cut

sub run {
   my $self = shift;
   my $delay = @_ ? shift : 0.25;
   $self->_read while (!select(undef,undef,undef,$delay));
}

sub _read {
   my $self = shift;
   foreach ($self->{'_SELECT'}->can_read(0)) {
      my $data;
      my $rv = $_->recv($data, POSIX::BUFSIZ, 0);
      die "Could not read from server: $@" unless defined($rv);
      $self->{'_BUFFER'} .= $data;
   }
   while ($self->{'_BUFFER'}=~s/^(.*?)\r?\n//) {
      $self->_parse($1);
   }
}

sub _parse {
   my $self = shift;
   my $line = shift;

   if ($line =~ /^\*TIME: (\d+)$/) {
      $self->{'_SERVERTIME'}=$1;
      
   } elsif ($line =~ /^\*PROTOCOLS: (.*?)$/) {
      $self->{'_PROTOCOLS'} = $1;
      foreach (split(',',$self->{'_PROTOCOLS'})) {
	 $self->{'_CAPABILITY'}->{"$_"}='';
	 $self->{'_SOCKET'}->send( sprintf("!0 CAPABILITY %s\n", $_),0) or croak ("Could not send to server");
      }
      
   } elsif ($line =~ /^\*CAPABILITY: ([^ ]+) (.*?)$/) {
      $self->{'_CAPABILITY'}->{"$1"}=$2;

   } elsif ($line =~ /^\*KISMET: (.*?) (.*?) (.*?) (.*?)$/) {
      $self->{'_VERSION'} = $1;
      $self->{'_STARTTIME'} = $2;
      $self->{'_SERVERNAME'} = $3;
      $self->{'_BUILDREVISION'} = $4;
   
   }

   foreach (keys %{$self->{'_CAPABILITY'}}) {
      if ($line =~ /^\*$_: (.*?)$/) {
	 my %args;
	 if ((defined($1))&&(exists($self->{'_ENABLE'}->{"$_"}))) {
	    my @tmp = $self->_parse_fields($1);
	    if ($self->{'_ENABLE'}->{"$_"} eq '*') {
	       $self->{'_ENABLE'}->{"$_"}=$self->{'_CAPABILITY'}->{"$_"};
	    }
	    foreach (split(",",$self->{'_ENABLE'}->{"$_"})) {
	       $args{"$_"}=shift @tmp;
	    }
	 }
	 $self->send_event($_,%args);
	 last;
      }
   }
}

sub _parse_fields {
   my $self = shift;
   my $text = shift;
   my @fields;
   my $tmp='';
   my $bin = 0;
   while ($text =~ s/^(.)//) {
      if ((ord($1)==32) && ($bin==0)) {
	 push @fields, $tmp;
	 $tmp = '';
	 next;
      }
      if (ord($1)==1) {
	 $bin = not $bin;
	 next;
      }      
      $tmp.=$1;
   }
   if ($tmp ne '') {
      push @fields, $tmp;
   }
   return @fields;
}
	 
	 

sub send_event { 
   my ($self, $sig, @argv)=@_;
   $sig = uc($sig);
   foreach (@{$self->{'_HANDLERS'}->{"$sig"}}) {
      &{$_}(@argv) if defined(&{$_});
   }
}

=head2 add_handler

   $kismet->add_handler('NETWORK', \&event_network);

Adds a event handler to catch events.

=cut

sub add_handler {
   my ($self, $sig, $sub) = @_;
   $sig = uc($sig);
   push @{$self->{'_HANDLERS'}->{"$sig"}}, $sub;
}

=head2 enable

   $kismet->enable('NETWORK', 'ssid,bssid');

Sends a ENABLE command to the Kismet-server.

=cut
						   
sub enable {
   my ($self, $protocol, $fields) = @_;
   croak ("Not connected to Kismet server") unless $self->connected;
   $self->{'_SOCKET'}->send( sprintf("!0 ENABLE %s %s\n", $protocol, $fields),0) or croak ("Could not send to server");
   $self->{'_ENABLE'}->{"$protocol"} = $fields;
}

=head2 disable

   $kismet->disable('NETWORK');

Sends a REMOVE to the Kismet-server. Thi functions was renamed cos
of the IO::Select's remove function.

=cut

sub disable {
   my ($self, $protocol) = @_;
   croak ("Not connected to Kismet server") unless $self->connected;
   $self->{'_SOCKET'}->send(sprintf("!0 REMOVE %s\n", $protocol),0) or croak ("Could not send to server");
   delete($self->{'_ENABLE'}->{"$protocol"});
}

=head2 raw

   $kismet->raw('!123 ENABLE NETWORK ssid,bssid,wep');

Sends a raw-string to the Kismet-server

=cut

sub raw {
   my ($self, $raw) = @_;
   croak ("Not connected to Kismet server") unless $self->connected;
   $self->{'_SOCKET'}->send($raw,0) or croak ("Could not send to server");
}

=head2 capability

   $kismet->capability('NETWORK');

Return a comma-seperated list of fields for a command.

=cut

sub capability {
   my ($self, $protocol) = @_;
   return $self->{'_CAPABILITY'}->{"$protocol"} if (exists($self->{'_CAPABILITY'}->{"$protocol"}));
   return '';
}

=head2 protocols

   $kismet->protocols;

Returns a comma-seperated list of command.

=cut

sub protocols {
   my ($self) = @_;
   return $self->{'_PROTOCOLS'} if (exists($self->{'_PROTOCOLS'}));
   return '';
}

=head2 pause

   $kismet->pause;

Sends a PAUSE to the Kismet-server.

=cut

no warnings;
sub pause {
   my $self = shift;
   croak ("Not connected to Kismet server") unless $self->connected;
   $self->{'_SOCKET'}->send("!0 PAUSE\n",0) or croak ("Could not send to server");
}
use warnings;

=head2 resume

   $kismet->resume;

Sends a RESUME to the Kismet-server

=cut

sub resume {
   my $self = shift;
   croak ("Not connected to Kismet server") unless $self->connected;
   $self->{'_SOCKET'}->send("!0 RESUME\n",0) or croak ("Could not send to server");
}

1;

package ACLTestApp;

use strict;
use warnings;
no warnings 'uninitialized';

use Catalyst qw/
	Authentication
	Authentication::Store::Minimal
	Authentication::Credential::Password

	Authorization::Roles
	Authorization::ACL
/;

sub default : Private {
	my ( $self, $c ) = @_;
	$c->res->write( "welcome to the zoo!" );
	
}

sub restricted {
	my ( $self, $c ) = @_;
	$c->res->write( "restricted " );
}

sub end : Private {
	my ( $self, $c ) = @_;
	$c->res->write( $c->error->[-1] =~ /denied/ ? "denied" : "allowed" );
	$c->error( 0 );
}

__PACKAGE__->setup;

__PACKAGE__->deny_access_unless("/lioncage", sub { 0 });

__PACKAGE__->deny_access_unless("/restricted", sub { 0 });

__PACKAGE__

#!/usr/bin/perl

use strict;
use warnings;

close STDERR;

{
	package ACLTestApp::NoRoles;
	use Catalyst qw/-Debug -Engine=Test Authorization::ACL/;

	sub moose : Global { }

	sub elk : Local { }

	sub end : Private {
		my ( $self, $c ) = @_;
		$c->res->body( "allowed" );
	}

	__PACKAGE__->setup;

	__PACKAGE__->deny_access_unless( "/elk", sub {
		return 0;
	});
}

use Test::More 'no_plan';
use Catalyst::Test 'ACLTestApp::NoRoles';

is( get("/moose"), "allowed" );
like( get("/elk"), qr/access.*denied/i );


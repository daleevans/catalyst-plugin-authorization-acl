#!/usr/bin/perl

use strict;
use warnings;

{
	package ACLTestApp::NoRoles;
	use Catalyst qw/-Engine=Test Authorization::ACL/;

	sub moose : Global {
		my ( $self, $c ) = @_;
		$c->res->body("moose");
	}

	sub elk : Local {
		my ( $self, $c ) = @_;
		warn "elk is running!";
		$c->res->body("elk");
	}

	sub end : Private {
		my ( $self, $c ) = @_;
		$c->res->body( $c->res->body . " " . ( @{ $c->error } ? "denied" : "allowed" ) );
		$c->error(0);
	}

	__PACKAGE__->setup;

	__PACKAGE__->deny_access_unless( "/elk", sub { 0 });
}

use Test::More 'no_plan';
use Catalyst::Test 'ACLTestApp::NoRoles';

is( get("/moose"), "moose allowed" );
is( get("/elk"),   " denied"    );


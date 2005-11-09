#!/usr/bin/perl

use strict;
use warnings;

use lib "t/lib";

use Test::More 'no_plan';
use Test::WWW::Mechanize::Catalyst 'ACLTestApp';

my $m = Test::WWW::Mechanize::Catalyst->new;

my $u = "http://localhost";

is_allowed("", "welcome");

is_denied("restricted");
is_denied("lioncage");
is_denied("zoo/elk");
is_denied("zoo/moose");
is_denied("zoo/rabbit");

login(qw/foo bar/);

is_allowed("auth/check", "logged in");

is_denied("restricted");
is_denied("lioncage");
is_allowed("zoo/elk");
is_denied("zoo/moose");
is_denied("zoo/rabbit");

is_allowed("auth/logout");

is_denied("restricted");
is_denied("lioncage");
is_denied("zoo/elk");
is_denied("zoo/moose");
is_denied("zoo/rabbit");

login(qw/gorch moose/);

is_allowed("zoo/elk");
is_denied("zoo/moose");
is_allowed("zoo/rabbit");
is_denied("lioncage");
is_denied("restricted");

login(qw/quxx ding/);

is_allowed("zoo/elk");
is_allowed("zoo/moose");
is_denied("zoo/rabbit");
is_denied("lioncage");
is_denied("restricted");

sub login {
	my ( $l, $p ) = @_;
	is_allowed("auth/login?login=$l&password=$p", "login successful");
}

sub is_denied {
	my $path = shift;
	local $Test::Builder::Level = 2;
	$m->get_ok("$u/$path", "get '$path'");
	$m->content_is("denied", "access to '$path' is denied");
}

sub is_allowed {
	my ( $path, $contains ) = @_;
	$path ||= "";
	$m->get_ok("$u/$path", "get '$path'");
	$m->content_contains( $contains, "'$path' contains '$contains'") if $contains;
	$m->content_like(qr/allowed$/, "access to '$path' is allowed");
}

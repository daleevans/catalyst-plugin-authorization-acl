#!/usr/bin/perl

use strict;
use warnings;

use lib "t/lib";

use Test::More 'no_plan';
use Test::WWW::Mechanize::Catalyst 'ACLTestApp';

my $m = Test::WWW::Mechanize::Catalyst->new;

my $u = "http://localhost";

$m->get_ok($u, "load index");
$m->content_contains("welcome", "welcome message");
$m->content_like(qr/allowed$/, "access allowed");

$m->get_ok("$u/lioncage", "load lion cage");
$m->content_is("denied", "access denied, no output");

#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL;
use base qw/Class::Data::Inheritable/;

use strict;
use warnings;

use Scalar::Util ();
use Catalyst::Plugin::Authorization::ACL::Engine;

BEGIN { __PACKAGE__->mk_classdata("_acl_engine") }

sub execute {
    my ( $c, $class, $action ) = @_;

	local $NEXT::NEXT{$c, "execute"};

    if ( Scalar::Util::blessed($action) ) {
		eval { $c->_acl_engine->check_action_rules( $c, $action ) };

		if ( my $err = $@ ) {
			return $c->NEXT::execute( $class, sub { die $err });
		}
		
    }

    $c->NEXT::execute( $class, $action );
}

sub setup {
    my $app = shift;
    my $ret = $app->NEXT::setup( @_ );

    $app->_acl_engine( Catalyst::Plugin::Authorization::ACL::Engine->new($app) );
    
    $ret;
}

sub deny_access_unless {
    my $c = shift;
    $c->_acl_engine->add_deny( @_ );
}

sub allow_access_if {
    my $c = shift;
    $c->_acl_engine->add_allow( @_ );
}

sub acl_add_rule {
    my $c = shift;
    $c->_acl_engine->add_rule( @_ );
}

__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authorization::ACL - ACL support for Catalyst controllers and
URIs.

=head1 SYNOPSIS

	use Catalyst qw/
		Authentication
		Authorization::Foo
		Authorization::ACL
	/;

	__PACKAGE__->setup;

	# deny if the check is false
	__PACKAGE__->deny_access_unless(
		"/foo/bar",
		..., # see below on how to specify a rule predicate
	);

	# allow if the check is true
	__PACKAGE__>allow_access_if(
		"/foo/bar/gorch",
		...,
	);

=head1 DESCRIPTION

This module provides authorization ACLs for two related namespaces Catalyst
applications have:

=over 4

=item Private Namepsace

Every action has it's own private path. This path reflects the Perl namespaces
the actions were born in, and the namespaces of their controllers.

=item External namespace

Some actions are also accessible from the outside, via another path.

This path is usually the same, if you used C<Local>. Alternatively you can use
C<Path>, C<Regex>, or C<Global> to specify a different external path for your
action.

=back

The ACL module currently only knows to exploit the private namespace. In the
future extensions may be made to support external namespaces as well.

=head1 METHODS

=item allow_access_if $path, $predicate

=item deny_access_unless $path, $predicate

Adds a rule to all the actions under C<$path>. C<$predicate> can take the
following forms:

	__PACAKGE__->deny_access_unless(
		"/foo",
		"foo", # calls $c->foo( $action ), expects boolean return
	);

	__PACAKGE__->deny_access_unless(
		"/foo",
		sub { }, # calls $subref->( $c, $action ), expects boolean return
	);

	__PACAKGE__->deny_access_unless(
		"/foo",
		[qw/list of roles/], # delegates to Authorization::Roles
	);

Note - C<allow_access_if> will have no effect unless a more general
C<deny_access_unless> rule also applies to the action.

=item acl_add_rule $path, $rule, [ $filter ]

Manually add a rule to all the actions under C<$path> using the more flexible (but
more verbose) method:

	__PACKAGE__->acl_add_rule(
		"/foo",
		sub {
			my ( $c, $action ) = @_;
			# die with $Catalyst::Plugin::Authorization::ACL::Engine::DENIED to deny access
			# die with $Catalyst::Plugin::Authorization::ACL::Engine::ALLOWED to allow access
			# otherwise the next rule for this action is tried
		},
		sub {
			my $action = shift;
			# return a true value if you want to apply the rule to this action
			# called for all the actions under "/foo"
		}
	};

In this case the rule must be a sub reference (or method name) to be invoked on
$c.
	
=cut



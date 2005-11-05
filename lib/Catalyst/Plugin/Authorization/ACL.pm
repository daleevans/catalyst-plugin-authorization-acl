#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL;
use base qw/Class::Data::Inheritable/;

use strict;
use warnings;

use Scalar::Util ();
use Catalyst::Plugin::Authorization::ACL::Engine;

BEGIN { __PACKAGE__->add_classdata("_acl_engine") }

sub setup {
	my $class = shift;

	$class->_acl_engine(
		Catalyst::Plugin::Authorization::ACL::Engine->new( $c );
}

sub execute {
	my ( $c, $class, $action ) = @_;

	if ( Scalar::Util::blessed( $action ) ) {
		$c->_acl_engine->check_action_rules( $action );
	}

	$c->NEXT::execute( $class, $action );
}

sub restrict_access {
	my $c = shift;
	$c->_acl_engine->restrict_access( @_ );
}

sub permit_access {
	my $c = shift;
	$c->_acl_engine->permit_access( @_ );
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

	__PACKAGE__->restrict_access(
		"/foo/bar",
		..., # see below on how to specify a permission
	);

	__PACKAGE__>permit_access(
		"My::Controller",
		...,
	);

	__PACKAGE__->setup;

=head1 DESCRIPTION

This module provides authorization ACLs for two related namespaces Catalyst
applications have:

=over 4

=item Private Namepsace

Every action is placed somewhere in the private L<Catalyst> namespace under
some controller.  This is the perl package of the code reference the action is
defined as, or the path you C<forward> to.

=item External namespace

Every action also has some sort of path within the application that it can be
referred by. This is probably almost equivalent to the private namespace, but
is technically orthogonal.

=back

This module performs authorization checks automatically for you, based on the
request URI, and all the dispatches.

=cut



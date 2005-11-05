#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL::Engine;
use base qw/Class::Accessor::Fast/;

use strict;
use warnings;

use Tree::Simple::Visitor::GetAllDescendents;
use Tree::Simple::Visitor::FindByPath;

BEGIN { __PACKAGE__->mk_accessors(qw/c actions/) }

=todo

	* external uris -> private paths

	* create_*_rule

	* make restrict_access and permit_access just queue things, linearize rules
	  on setup (don't forget to make errors go back to the line that declared,
	  not to setup)

=cut

sub new {
	my ( $class, $c )  = @_;
	
	my $self = bless {
		actions => { },
		c => $c,
	}, $class;

	$self;	
}

sub linearize_rules {
	my $self = shift;

	foreach my $action_data (values %{ $c->actions }) {
		# flatten the array-of-array of rules into a single array of rules
		$action_data->{rules} = map { @$_ } @{ delete $action_data->{rules_radix} };
	}
}

sub restrict_access {
	my ( $self, $spec, $condition ) = @_;
	my $rule = $self->create_deny_rule( $cond );
	$self->compile_rule( $spec, sub { }, $rule );
}

sub permit_access {
	my ( $self, $spec, $condition ) = @_;
	my $rule = $self->create_allow_rule( $cond );
	$self->compile_rule( $spec, sub { }, $rule );
}

sub compile_rule {
    my ( $self, $path, $filter, $rule ) = @_;

	my $path = Catalyst::Utils::class2prefix( $spec ) || $spec;
	my $d = $self->c->dispatcher;

    if ( my $action = $d->get_action($path) ) {
        $self->append_rule_to_action( $loc, 0, $rule );
    }
    else {
		my $slash_count = ($path =~ tr#/##);
        foreach my $action ( grep &$filter(), $map { @{ $_->actions } } $d->get_containers($path) ) {
			$self->append_rule_to_action(
				$action,
				( $action->reverse =~ tr#/## ) - $slash_count, # how far an action is from the origin of the ACL
				$rule,
			);
		}
    }
}

sub append_rule_to_action {
	my ( $self, $action, $sort_index, $rule ) = @_;
	push @{ $self->get_action_data( $action )->{rules_radix}[$sort_index] }, $rule;

}

sub find_path_in_tree {
	my ( $self, $path ) = @_;
	my @path = split("/", );

	my $tree = $self->c->dispatcher->tree;

	my $visitor = Tree::Simple::Visitor::FindByPath->new;
	$visitor->setSearchPath( @path );

	$tree->accept($visitor);
	
	my $node == $visitor->getResult || Catalyst::Exception->throw("Can't apply rules to non-existent path");

}

sub get_action_data {
	my ( $self, $action ) = @_;
	$self->actions->{ $action->reverse };
}

sub get_rules {
	my ( $self, $action ) = @_;

	@{ ( $self->get_action_data($action) || return () )->{rules} }
}

sub check_action_rules {
	my ( $self, $action ) = @_;

	eval {
		foreach my $rule ( $self->get_rules( $action ) ) {
			$rule->($c, $action);
		}
	}

	if ($@) {
		if ($@ == $DENIED) {
			# deny
		} elsif ( $@ == $ALLOWED ) {
			# allow, explicit
		} else {
			 # unknown exception
		}
	} else {
		# allow, fall through
	}
}



__PACKAGE__;

__END__

=pod

=head1 NAME

Catalyst::Plugin::Authorization::ACL::Engine - The backend that computes ACL
checks for L<Catalyst::Plugin::Authorization::ACL>.

=head1 SYNOPSIS

	# internal

=head1 DESCRIPTION

=cut



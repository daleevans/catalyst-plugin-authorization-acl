#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL::Engine;
use base qw/Class::Accessor::Fast/;

use strict;
use warnings;

use Class::Throwable;

BEGIN { __PACKAGE__->mk_accessors(qw/app actions/) }

=todo

	* external uris -> private paths

=cut

our $DENIED  = bless {}, __PACKAGE__ . "::Denied";
our $ALLOWED = bless {}, __PACKAGE__ . "::Allowed";

sub new {
    my ( $class, $c ) = @_;

    my $self = bless {
        actions => {},
        app     => $c,
    }, $class;

    $self;
}

sub add_deny {
    my ( $self, $spec, $condition ) = @_;

    my $test = $self->fudge_condition($condition);

    $self->add_rule(
        $spec,
        sub {
            my $c = shift;
            die $DENIED unless $c->$test(@_);
        },
    );
}

sub add_allow {
    my ( $self, $spec, $condition ) = @_;

    my $test = $self->fudge_condition($condition);

    $self->add_rule(
        $spec,
        sub {
            my $c = shift;
            die $ALLOWED if $c->$test(@_);
        },
    );
}

sub fudge_condition {
    my ( $self, $condition ) = @_;

    # make almost anything into a code ref/method name
    if ( my $reftype = ref $condition ) {
        $reftype eq "CODE" and return $condition;

        # if it's not a code ref and it's a ref, we only know
        # how to deal with it if it's an array of roles
        $reftype ne "ARRAY"
          and die "Can't interpret '$condition' as an ACL condition";

        # but to check roles we need the appropriate plugin
        $self->app->isa("Catalyst::Plugin::Authorization::Roles")
          or die "Can't use role list as an ACL condition unless "
          . "the Authorization::Roles plugin is also loaded.";

        # return a test that will check for the roles
        return sub {
            my $c = shift;
            $c->check_user_roles(@$condition);
        };
    }
    else {
        $self->app->can($condition)
          or die "Can't use string '$condition' as an ACL "
          . "condition unless \$c->can('$condition').";

        return $condition;    # just a method name
    }
}

sub add_rule {
    my ( $self, $path, $rule, $filter ) = @_;
    $filter ||= sub { 1 };

    my $d = $self->app->dispatcher;

    if ( my $action = $d->get_action( $path =~ m#^(.*?)([^/]+)$# ) ) {
        $self->append_rule_to_action( $action, 0, $rule );
    }
    else {
        my $slash_count = ( $path =~ tr#/## );
        foreach my $action (
            grep { $filter->($_) }
              map  { values %{ $_->actions } }
                $d->get_containers($path)
          )
        {
            $self->append_rule_to_action(
                $action,
                ( $action->reverse =~ tr#/## ) - $slash_count
                ,    # how far an action is from the origin of the ACL
                $rule,
            );
        }
    }
}

sub append_rule_to_action {
    my ( $self, $action, $sort_index, $rule ) = @_;
    push @{ $self->get_action_data($action)->{rules_radix}[$sort_index] }, $rule;

}

sub get_action_data {
    my ( $self, $action ) = @_;
    $self->actions->{ $action->reverse } ||= {};
}

sub get_rules {
    my ( $self, $action ) = @_;

    map { @$_ } @{ ( $self->get_action_data($action) || return () )->{rules_radix} };
}

sub check_action_rules {
    my ( $self, $c, $action ) = @_;

    my $last_rule;
    eval {
        foreach my $rule ( $self->get_rules($action) ) {
            $last_rule = $rule;
            $c->$rule($action);
        }
    };

    if ($@) {
        if ( ref $@ and $@ == $DENIED ) {
            die "Access to $action denied by rule $last_rule.\n";
        }
        elsif ( ref $@ and $@ == $ALLOWED ) {
            return;
        }
        else {

            # unknown exception
            # FIXME - add context (the user should know what rule
            # generated the exception, and where it was added)
            Class::Throwable->throw(
                "An error occurred while evaluating ACL rules.", $@ );
        }
    }

    # no rules means allow by default
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



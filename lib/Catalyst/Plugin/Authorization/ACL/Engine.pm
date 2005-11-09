#!/usr/bin/perl

package Catalyst::Plugin::Authorization::ACL::Engine;
use base qw/Class::Accessor::Fast/;

use strict;
use warnings;

# I heart stevan
use Class::Throwable;
use Tree::Simple::Visitor::FindByPath;
use Tree::Simple::Visitor::GetAllDescendents;

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
    $filter ||= sub { $_[0]->name !~ /^_/ }; # internal actions are not ACL'd

    my $d = $self->app->dispatcher;

    my ($ns, $name) = $path =~ m#^/?(.*?)/?([^/]+)$#;

    if ( my $action = $d->get_action( $name, $ns ) ) {
        $self->app->log->debug("Adding ACL rule to the action $path") if $self->app->debug;
        $self->append_rule_to_action( $action, 0, $rule );
    }
    else {
        my $tree = $d->tree;

        my $by_path = Tree::Simple::Visitor::FindByPath->new;
        $by_path->setSearchPath( grep { $_ ne "" } split( "/", $path ) );
        $tree->accept($by_path);

        my $subtree = $by_path->getResult
          || Catalyst::Exception->throw("The path '$path' does not exist (traversal hit a dead end at: @{[ map { $_->getNodeValue } $by_path->getResults ]})");
        my $root_depth = $subtree->getDepth;

        my $descendents = Tree::Simple::Visitor::GetAllDescendents->new;
        $subtree->accept($descendents);
        
        $self->app->log->debug("Adding ACL rule to the namespace $path") if $self->app->debug;

        foreach my $node ( $subtree, $descendents->getAllDescendents ) {
            my ( $container, $depth ) = ( $node->getNodeValue, $node->getDepth );

            foreach my $action ( grep { $filter->($_) }
                values %{ $container->actions } )
            {
                $self->app->log->debug( "... $action" ) if $self->app->debug;
                $self->append_rule_to_action(
                    $action,
                    1 + ( $depth - $root_depth ), # how far an action is from the origin of the ACL
                    $rule,
                );
            }
        }
    }
}

sub append_rule_to_action {
    my ( $self, $action, $sort_index, $rule ) = @_;
    $sort_index = 0 if $sort_index < 0;
    push @{ $self->get_action_data($action)->{rules_radix}[$sort_index] ||=
          [] }, $rule;

}

sub get_action_data {
    my ( $self, $action ) = @_;
    $self->actions->{ $action->reverse } ||= { action => $action };
}

sub get_rules {
    my ( $self, $action ) = @_;

    map { $_ ? @$_ : () }
      @{ ( $self->get_action_data($action) || return () )->{rules_radix} };
}

sub check_action_rules {
    my ( $self, $c, $action ) = @_;

    my $last_rule;
    eval {
        foreach my $rule ( $self->get_rules($action) )
        {
            $c->log->debug("running ACL rule $rule on $action") if $c->debug;
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



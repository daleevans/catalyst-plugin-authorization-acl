package ACLTestApp2;

use strict;
use warnings;
no warnings 'uninitialized';

use Catalyst qw/
  Authorization::ACL
  /;

sub foo : Local {
    my ( $self, $c ) = @_;
    $c->res->body("foo");
}

sub bar : Local {
    my ( $self, $c ) = @_;
    $c->res->body("bar");
}

sub end : Private {
    my ( $self, $c ) = @_;

    $c->res->body( join " ", ( $c->stash->{denied} || @{ $c->error } ? "denied" : "allowed" ),
        $c->res->body );
}

sub access_denied : Private {
    my ( $self, $c, $action ) = @_;

    $c->res->body( join " ", "handled", $c->res->body );

    $c->stash->{denied} = 1;
    die $Catalyst::DETACH;
}

__PACKAGE__->setup;

__PACKAGE__->deny_access_unless( "/", 0 );

__PACKAGE__->allow_access_if( "/bar", 1 );


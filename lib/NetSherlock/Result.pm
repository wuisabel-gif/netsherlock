package NetSherlock::Result;

use strict;
use warnings;

use JSON::PP ();

=head1 NAME

NetSherlock::Result - structured evidence from a single check

=head1 DESCRIPTION

Every measurement module returns one of these. Failures are not reduced
to a boolean: the C<status> field carries an explicit state such as
C<timeout>, C<connection_refused>, C<dns_failure>, C<host_unreachable>,
C<network_unreachable>, C<permission_denied>, C<unsupported>, C<skipped> or
C<unknown>.

Check-specific extras (addresses, hops, protocol, ...) live in C<detail>.

=cut

sub new {
    my ( $class, %args ) = @_;

    my $self = {
        check      => $args{check}      // 'unknown',
        target     => $args{target},
        port       => $args{port},
        success    => $args{success}    // 0,
        status     => $args{status}     // 'unknown',
        latency_ms => $args{latency_ms},
        error      => $args{error},
        detail     => $args{detail} || {},
    };

    return bless $self, $class;
}

sub check      { return $_[0]->{check} }
sub target     { return $_[0]->{target} }
sub port       { return $_[0]->{port} }
sub success    { return $_[0]->{success} }
sub status     { return $_[0]->{status} }
sub latency_ms { return $_[0]->{latency_ms} }
sub error      { return $_[0]->{error} }
sub detail     { return $_[0]->{detail} }

sub ok { return $_[0]->{success} ? 1 : 0 }

# Plain hashref suitable for JSON encoding. Undef optional fields are
# omitted so the machine-readable output stays clean.
sub to_hash {
    my ($self) = @_;

    my %h = (
        check   => $self->{check},
        success => $self->{success} ? $JSON::PP::true : $JSON::PP::false,
        status  => $self->{status},
    );

    $h{target}     = $self->{target}         if defined $self->{target};
    $h{port}       = $self->{port} + 0       if defined $self->{port};
    $h{latency_ms} = $self->{latency_ms} + 0 if defined $self->{latency_ms};
    $h{error}      = $self->{error}          if defined $self->{error};
    $h{detail}     = $self->{detail}         if %{ $self->{detail} };

    return \%h;
}

1;

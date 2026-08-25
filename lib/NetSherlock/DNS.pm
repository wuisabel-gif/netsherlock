package NetSherlock::DNS;

use strict;
use warnings;

use Socket qw(getaddrinfo getnameinfo inet_pton
  NI_NUMERICHOST NI_NUMERICSERV SOCK_STREAM AF_INET AF_INET6);
use Time::HiRes ();

use NetSherlock::Result;

=head1 NAME

NetSherlock::DNS - hostname resolution evidence

=head1 DESCRIPTION

Resolves a hostname via the operating system resolver (getaddrinfo) and
returns a NetSherlock::Result. A coderef resolver can be injected for
deterministic tests.

=cut

# True when the string is already a numeric IPv4 or IPv6 address.
sub is_ip_literal {
    my ($host) = @_;
    return 0 unless defined $host;
    return 1 if inet_pton( AF_INET,  $host );
    return 1 if inet_pton( AF_INET6, $host );
    return 0;
}

# resolve(host => $host, logger => $coderef, resolver => $coderef)
#
# The optional resolver receives the hostname and returns
# ($error, @addresses), mirroring _system_resolve.
sub resolve {
    my (%args) = @_;

    my $host = $args{host};
    die 'NetSherlock::DNS::resolve requires a host' unless defined $host;

    my $logger   = $args{logger};
    my $resolver = $args{resolver};

    $logger->("resolving $host") if $logger;

    my $start = Time::HiRes::time();
    my ( $err, @addresses );

    if ($resolver) {
        ( $err, @addresses ) = $resolver->($host);
    }
    else {
        ( $err, @addresses ) = _system_resolve($host);
    }

    my $latency = _ms_since($start);

    if ($err) {
        $logger->("resolution failed for $host: $err") if $logger;
        return NetSherlock::Result->new(
            check      => 'dns',
            target     => $host,
            success    => 0,
            status     => 'dns_failure',
            latency_ms => $latency,
            error      => "$err",
        );
    }

    if ( !@addresses ) {
        $logger->("resolution of $host returned no addresses") if $logger;
        return NetSherlock::Result->new(
            check      => 'dns',
            target     => $host,
            success    => 0,
            status     => 'dns_failure',
            latency_ms => $latency,
            error      => 'resolver returned no addresses',
        );
    }

    # De-duplicate while preserving order.
    my %seen;
    my @unique = grep { !$seen{$_}++ } @addresses;

    $logger->( "resolved $host -> " . join( ', ', @unique ) ) if $logger;

    return NetSherlock::Result->new(
        check      => 'dns',
        target     => $host,
        success    => 1,
        status     => 'success',
        latency_ms => $latency,
        detail     => { addresses => \@unique },
    );
}

# Returns ($error, @numeric_addresses) using the OS resolver.
sub _system_resolve {
    my ($host) = @_;

    my ( $err, @res ) = getaddrinfo( $host, undef, { socktype => SOCK_STREAM } );
    return ($err) if $err;

    my @addresses;
    for my $entry (@res) {
        my ( $nerr, $node ) =
          getnameinfo( $entry->{addr}, NI_NUMERICHOST, NI_NUMERICSERV );
        push @addresses, $node unless $nerr;
    }

    return ( undef, @addresses );
}

sub _ms_since {
    my ($start) = @_;
    return sprintf( '%.1f', ( Time::HiRes::time() - $start ) * 1000 ) + 0;
}

1;

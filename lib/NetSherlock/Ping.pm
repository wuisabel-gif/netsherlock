package NetSherlock::Ping;

use strict;
use warnings;

use Net::Ping ();
use Time::HiRes ();

use NetSherlock::Result;

=head1 NAME

NetSherlock::Ping - basic host reachability evidence

=head1 DESCRIPTION

Wraps Net::Ping and returns a NetSherlock::Result.

Protocol selection: C<icmp> when running as root (raw sockets), otherwise
C<syn>, which needs no privileges and treats a TCP RST as proof the host
is alive. A failed ping therefore does NOT prove the host is down; the
diagnosis layer accounts for that.

=cut

sub default_protocol {
    return $< == 0 ? 'icmp' : 'syn';
}

# check(host => $host, timeout => $seconds, protocol => $proto, logger => $coderef)
sub check {
    my (%args) = @_;

    my $host = $args{host};
    die 'NetSherlock::Ping::check requires a host' unless defined $host;

    my $timeout = $args{timeout};
    $timeout = 5 unless defined $timeout && $timeout > 0;

    my $protocol = $args{protocol} // default_protocol();
    my $logger   = $args{logger};

    $logger->("pinging $host (protocol $protocol, timeout ${timeout}s)")
      if $logger;

    my $pinger = eval { Net::Ping->new( $protocol, $timeout ) };
    if ( !$pinger ) {
        my $err = $@ || 'unknown error';
        chomp $err;
        return NetSherlock::Result->new(
            check   => 'ping',
            target  => $host,
            success => 0,
            status  => 'unknown',
            error   => "cannot create ping object ($protocol): $err",
            detail  => { protocol => $protocol },
        );
    }

    my $start = Time::HiRes::time();
    my ( $ok, $duration, $ip ) = eval { $pinger->ping( $host, $timeout ) };
    $pinger->close;

    if ($@) {
        my $err = $@;
        chomp $err;
        return NetSherlock::Result->new(
            check   => 'ping',
            target  => $host,
            success => 0,
            status  => 'unknown',
            error   => $err,
            detail  => { protocol => $protocol },
        );
    }

    my $latency = _ms_since($start);

    if ($ok) {
        $logger->("ping to $host succeeded in ${latency} ms") if $logger;
        return NetSherlock::Result->new(
            check      => 'ping',
            target     => $host,
            success    => 1,
            status     => 'success',
            latency_ms => $latency,
            detail     => { protocol => $protocol, ip => $ip },
        );
    }

    if ( !defined $ip || $ip eq '' ) {
        $logger->("ping could not resolve $host") if $logger;
        return NetSherlock::Result->new(
            check      => 'ping',
            target     => $host,
            success    => 0,
            status     => 'dns_failure',
            latency_ms => $latency,
            error      => "could not resolve $host",
            detail     => { protocol => $protocol },
        );
    }

    $logger->("ping to $host: no response within ${timeout}s") if $logger;
    return NetSherlock::Result->new(
        check      => 'ping',
        target     => $host,
        success    => 0,
        status     => 'timeout',
        latency_ms => $latency,
        error      => "no response within ${timeout}s (protocol $protocol)",
        detail     => { protocol => $protocol, ip => $ip },
    );
}

sub _ms_since {
    my ($start) = @_;
    return sprintf( '%.1f', ( Time::HiRes::time() - $start ) * 1000 ) + 0;
}

1;

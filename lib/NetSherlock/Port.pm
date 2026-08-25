package NetSherlock::Port;

use strict;
use warnings;

use Socket qw(getaddrinfo
  SOCK_STREAM IPPROTO_TCP SOL_SOCKET SO_ERROR);
use Errno qw(ECONNREFUSED ETIMEDOUT EHOSTUNREACH ENETUNREACH
  EACCES EPERM EINPROGRESS EWOULDBLOCK);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use Time::HiRes ();

use NetSherlock::Result;

=head1 NAME

NetSherlock::Port - TCP connect evidence with explicit failure states

=head1 DESCRIPTION

Performs a non-blocking TCP connect with a strict timeout and maps the
result to an explicit status:

    success, timeout, connection_refused, host_unreachable,
    network_unreachable, permission_denied, dns_failure, unknown

A refused connection, a silent timeout and an unreachable network are
different failures and are reported as such, because the diagnosis layer
reasons about their difference.

=cut

my %ERRNO_STATUS = (
    ECONNREFUSED()  => 'connection_refused',
    ETIMEDOUT()     => 'timeout',
    EHOSTUNREACH()  => 'host_unreachable',
    ENETUNREACH()   => 'network_unreachable',
    EACCES()        => 'permission_denied',
    EPERM()         => 'permission_denied',
);

sub status_from_errno {
    my ($errno) = @_;
    return 'unknown' unless defined $errno;
    return $ERRNO_STATUS{$errno} || 'unknown';
}

# check(host => $host, port => $port, timeout => $seconds, logger => $coderef,
#       resolver => $coderef, connector => $coderef)
#
# resolver and connector are optional dependency-injection hooks for
# deterministic tests. A resolver returns ($error, @addrinfo-like hashes);
# a connector returns ($status, $error).
sub check {
    my (%args) = @_;

    my $host = $args{host};
    my $port = $args{port};
    die 'NetSherlock::Port::check requires a host' unless defined $host;
    die 'NetSherlock::Port::check requires a port' unless defined $port;

    my $timeout = $args{timeout};
    $timeout = 5 unless defined $timeout && $timeout > 0;

    my $logger    = $args{logger};
    my $resolver  = $args{resolver};
    my $connector = $args{connector};

    $logger->("attempting TCP $host:$port (timeout ${timeout}s)") if $logger;

    my ( $rerr, @addresses );
    if ($resolver) {
        ( $rerr, @addresses ) = $resolver->( $host, $port );
    }
    else {
        ( $rerr, @addresses ) =
          getaddrinfo( $host, $port, { socktype => SOCK_STREAM, protocol => IPPROTO_TCP } );
    }

    if ($rerr) {
        return NetSherlock::Result->new(
            check   => 'tcp',
            target  => $host,
            port    => $port,
            success => 0,
            status  => 'dns_failure',
            error   => "$rerr",
        );
    }

    if ( !@addresses ) {
        return NetSherlock::Result->new(
            check   => 'tcp',
            target  => $host,
            port    => $port,
            success => 0,
            status  => 'unknown',
            error   => 'getaddrinfo returned no addresses',
        );
    }

    # Try every resolved address within one shared time budget.
    my $overall_start = Time::HiRes::time();
    my $deadline      = $overall_start + $timeout;
    my @attempts;

    for my $addr (@addresses) {
        my $start = Time::HiRes::time();
        my ( $status, $error ) = $connector
          ? $connector->( $addr, $deadline )
          : _try_connect( $addr, $deadline );
        my $latency = _ms_since($start);
        push @attempts, { status => $status, error => $error, latency_ms => $latency };

        if ( $status eq 'success' ) {
            $logger->("connected to $host:$port in ${latency} ms") if $logger;
            return NetSherlock::Result->new(
                check      => 'tcp',
                target     => $host,
                port       => $port,
                success    => 1,
                status     => 'success',
                latency_ms => $latency,
            );
        }

        last if Time::HiRes::time() >= $deadline;    # shared budget is spent
    }

    my $status = _choose_failure(@attempts);
    my ($selected) = grep { $_->{status} eq $status } @attempts;
    my $latency = _ms_since($overall_start);
    my $error = $selected ? $selected->{error} : undef;
    $logger->("TCP $host:$port $status after ${latency} ms") if $logger;
    return NetSherlock::Result->new(
        check      => 'tcp',
        target     => $host,
        port       => $port,
        success    => 0,
        status     => $status,
        latency_ms => $latency,
        error      => $error,
    );
}

sub _choose_failure {
    my (@attempts) = @_;
    return 'unknown' unless @attempts;

    # A timeout is the most useful result when no address answered. Prefer
    # explicit routing/permission errors over a generic unknown state, while
    # retaining refusal when every tried address refused the connection.
    for my $preferred (qw(timeout network_unreachable host_unreachable permission_denied connection_refused unknown)) {
        return $preferred if grep { $_->{status} eq $preferred } @attempts;
    }
    return 'unknown';
}

# Non-blocking connect bounded by an absolute deadline.
# Returns ($status, $error_string).
sub _try_connect {
    my ( $addr, $deadline ) = @_;

    my $proto = getprotobyname('tcp');
    my $fh;
    if ( !socket( $fh, $addr->{family}, SOCK_STREAM, $proto ) ) {
        return ( 'unknown', "socket: $!" );
    }

    my $flags = fcntl( $fh, F_GETFL, 0 );
    fcntl( $fh, F_SETFL, $flags | O_NONBLOCK );

    if ( connect( $fh, $addr->{addr} ) ) {
        return ('success');    # possible on loopback
    }

    if ( !$!{EINPROGRESS} && !$!{EWOULDBLOCK} ) {
        my $errno = 0 + $!;
        return ( status_from_errno($errno), _errno_string($errno) );
    }

    my $remaining = $deadline - Time::HiRes::time();
    return ( 'timeout', undef ) if $remaining <= 0;

    my $wfd = '';
    vec( $wfd, fileno($fh), 1 ) = 1;
    my $nready = select( undef, $wfd, $wfd, $remaining );

    if ( !defined $nready || $nready < 0 ) {
        return ( 'unknown', "select: $!" );
    }
    if ( $nready == 0 ) {
        return ( 'timeout', "no response within the timeout" );
    }

    my $packed = getsockopt( $fh, SOL_SOCKET, SO_ERROR );
    return ( 'unknown', 'getsockopt(SO_ERROR) failed' ) unless defined $packed;

    my $errno = unpack 'i', $packed;
    return ('success') if $errno == 0;

    return ( status_from_errno($errno), _errno_string($errno) );
}

sub _errno_string {
    my ($errno) = @_;
    local $! = $errno;
    return "$!";
}

sub _ms_since {
    my ($start) = @_;
    return sprintf( '%.1f', ( Time::HiRes::time() - $start ) * 1000 ) + 0;
}

1;

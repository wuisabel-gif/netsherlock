use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use IO::Socket::INET;
use Errno qw(ECONNREFUSED);
use Test::More;

use NetSherlock::Port;

my $server = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1',
    LocalPort => 0,
    Listen    => 5,
    Proto     => 'tcp',
    ReuseAddr => 1,
);
ok $server, 'temporary TCP server created' or BAIL_OUT('cannot create local TCP server');
my $open_port = $server->sockport;
my $pid = fork;
BAIL_OUT('fork failed') unless defined $pid;
if ( !$pid ) {
    $SIG{TERM} = sub { exit 0 };
    while ( my $client = $server->accept ) {
        close $client;
    }
    exit 0;
}
ok 1, 'forked local TCP server child';

my $open = NetSherlock::Port::check(
    host    => '127.0.0.1',
    port    => $open_port,
    timeout => 1,
);
ok $open->success, 'open TCP port succeeds';
is $open->status, 'success', 'open TCP port has success status';

kill 'TERM', $pid;
waitpid $pid, 0;
close $server;

my $closed_listener = IO::Socket::INET->new(
    LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'tcp', ReuseAddr => 1,
);
ok $closed_listener, 'temporary closed-port fixture created';
my $closed_port = $closed_listener->sockport;
close $closed_listener;

my $closed = NetSherlock::Port::check(
    host    => '127.0.0.1',
    port    => $closed_port,
    timeout => 1,
);
ok !$closed->success, 'closed TCP port fails';
is $closed->status, 'connection_refused', 'closed TCP port is distinguished from timeout';

my $timeout = NetSherlock::Port::check(
    host      => 'fixture.example',
    port      => 443,
    timeout   => 0.01,
    resolver  => sub { return ( undef, { fixture => 1 } ) },
    connector => sub { return ( 'timeout', 'fixture timeout' ) },
);
ok !$timeout->success, 'injected TCP timeout fails';
is $timeout->status, 'timeout', 'TCP timeout is represented explicitly';
like $timeout->error, qr/fixture timeout/, 'TCP error is retained';

my $fallback_calls = 0;
my $fallback = NetSherlock::Port::check(
    host      => 'fixture.example',
    port      => 443,
    resolver  => sub { return ( undef, { fixture => 1 }, { fixture => 2 } ) },
    connector => sub {
        ++$fallback_calls;
        return $fallback_calls == 1 ? ( 'connection_refused', 'first address refused' ) : ('success');
    },
);
ok $fallback->success, 'a later resolved address can succeed after an earlier refusal';
is $fallback_calls, 2, 'all useful resolved addresses are attempted';

is NetSherlock::Port::status_from_errno(ECONNREFUSED), 'connection_refused',
  'common refused errno maps to explicit status';

done_testing;

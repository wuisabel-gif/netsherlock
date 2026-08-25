use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Test::More;

use NetSherlock::Ping;

my $reachable = NetSherlock::Ping::check(
    host     => '127.0.0.1',
    protocol => 'syn',
    timeout  => 1,
);
ok $reachable->success, 'localhost is reachable using an unprivileged TCP probe';
is $reachable->status, 'success', 'reachable localhost has success status';

my $default = NetSherlock::Ping::default_protocol();
ok $default eq 'icmp' || $default eq 'syn', 'default ping protocol is supported';

done_testing;

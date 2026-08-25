use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Test::More;

use NetSherlock::DNS;

my $valid = NetSherlock::DNS::resolve(
    host     => 'fixture.example',
    resolver => sub { return ( undef, '192.0.2.10', '192.0.2.10', '2001:db8::10' ) },
);
ok $valid->success, 'injected valid DNS result succeeds';
is $valid->status, 'success', 'valid DNS has success status';
is_deeply $valid->detail->{addresses}, [ '192.0.2.10', '2001:db8::10' ],
  'addresses are de-duplicated in resolver order';

my $invalid = NetSherlock::DNS::resolve(
    host     => 'missing.example',
    resolver => sub { return ('NXDOMAIN') },
);
ok !$invalid->success, 'injected DNS error fails';
is $invalid->status, 'dns_failure', 'DNS error has explicit status';
like $invalid->error, qr/NXDOMAIN/, 'DNS error is retained';

ok NetSherlock::DNS::is_ip_literal('127.0.0.1'), 'IPv4 literal is recognized';
ok NetSherlock::DNS::is_ip_literal('2001:db8::1'), 'IPv6 literal is recognized';
ok !NetSherlock::DNS::is_ip_literal('host.example'), 'hostname is not an IP literal';

done_testing;

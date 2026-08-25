use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use JSON::PP ();
use Test::More;

use NetSherlock::Result;

my $result = NetSherlock::Result->new(
    check      => 'tcp',
    target     => '10.0.0.31',
    port       => 5432,
    success    => 0,
    status     => 'connection_refused',
    latency_ms => 1.8,
    detail     => { attempt => 1 },
);

is $result->check, 'tcp', 'check is retained';
is $result->status, 'connection_refused', 'explicit status is retained';
ok !$result->ok, 'failed result is not ok';
my $hash = $result->to_hash;
is $hash->{port}, 5432, 'port is represented numerically';
is $hash->{success}, JSON::PP::false, 'success is a JSON boolean';
is $hash->{detail}{attempt}, 1, 'check-specific detail is retained';

my $minimal = NetSherlock::Result->new( check => 'dns', success => 1, status => 'success' );
ok !exists $minimal->to_hash->{error}, 'undefined optional fields are omitted';

done_testing;

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Config ();
use File::Spec ();
use File::Temp qw(tempdir);
use Test::More;

use NetSherlock::Trace;

my $fixture = <<'TRACE';
traceroute to 192.0.2.20, 3 hops max
 1  192.0.2.1  1.20 ms
 2  2001:db8::1  4.50 ms
 3  * * *
TRACE

my $hops = NetSherlock::Trace::parse_output($fixture);
is scalar @$hops, 3, 'trace fixture yields three hops';
is_deeply $hops->[0]{addresses}, ['192.0.2.1'], 'IPv4 hop is parsed';
is_deeply $hops->[1]{addresses}, ['2001:db8::1'], 'IPv6 hop is parsed';
is $hops->[2]{no_response}, 1, 'missing hop is represented explicitly';
is $hops->[0]{rtts_ms}[0], 1.2, 'round-trip time is numeric';

# Put a deterministic sleeping traceroute first in PATH to exercise the
# process timeout without contacting any network.
my $dir = tempdir( CLEANUP => 1 );
my $fake = File::Spec->catfile( $dir, 'traceroute' );
open my $fake_fh, '>', $fake or die "cannot create fake traceroute: $!";
print {$fake_fh} "#!$Config::Config{perlpath}\nselect undef, undef, undef, 2;\n";
close $fake_fh or die "cannot close fake traceroute: $!";
chmod 0755, $fake or die "cannot make fake traceroute executable: $!";

{
    local $ENV{PATH} = $dir;
    my $timed = NetSherlock::Trace::check( host => '127.0.0.1', timeout => 0.1 );
    ok !$timed->success, 'traceroute process timeout fails';
    is $timed->status, 'timeout', 'traceroute timeout has explicit status';
}

done_testing;

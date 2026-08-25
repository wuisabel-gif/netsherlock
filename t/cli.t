use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use JSON::PP ();
use File::Temp qw(tempfile);
use Test::More;

my $cli = "$Bin/../bin/netsherlock";

my $version = `$cli --version`;
is $?, 0, 'version exits successfully';
like $version, qr/^NetSherlock \d+\.\d+\.\d+\n$/, 'version is printed';

my $help = `$cli dns --help`;
is $?, 0, 'command help exits successfully';
like $help, qr/Usage: netsherlock dns HOST/, 'command help names its command';

my $json = `$cli dns localhost --json`;
is $?, 0, 'successful DNS command exits zero';
my $document = eval { JSON::PP::decode_json($json) };
ok $document, 'successful JSON output parses';
is $document->{results}[0]{status}, 'success', 'JSON contains structured DNS status';

my $failure = `$cli port localhost 1 --json`;
is $?, 256, 'closed local port exits with network/service failure code';
my $failure_doc = JSON::PP::decode_json($failure);
is $failure_doc->{results}[-1]{status}, 'connection_refused', 'CLI preserves refusal status';

my $bad = `$cli port localhost not-a-port 2>&1`;
is $?, 512, 'invalid port exits with usage error code';
like $bad, qr/PORT must be an integer/, 'invalid port error is understandable';

my ( $config_fh, $config_path ) = tempfile();
print {$config_fh} <<'CONFIG';
hosts:
  web:
    address: 127.0.0.1
checks:
  - from: local
    to: web
    protocol: udp
    port: 53
CONFIG
close $config_fh;
my $bad_config = `$cli inspect $config_path 2>&1`;
is $?, 512, 'malformed configuration exits with usage/configuration code';
like $bad_config, qr/Invalid configuration/, 'configuration error is understandable';

done_testing;

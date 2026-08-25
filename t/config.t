use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use File::Temp qw(tempfile);
use Test::More;

use NetSherlock::Config;

my ( $fh, $path ) = tempfile();
print {$fh} <<'YAML';
hosts:
  web:
    address: 127.0.0.1
checks:
  - from: local
    to: web
    protocol: tcp
    port: 80
YAML
close $fh;

my $config = NetSherlock::Config->load_file($path);
is $config->{hosts}{web}{address}, '127.0.0.1', 'YAML host address is loaded';
is $config->{checks}[0]{protocol}, 'tcp', 'YAML check protocol is loaded';
is $config->{checks}[0]{port}, 80, 'YAML port is numeric';

my ( $json_fh, $json_path ) = tempfile();
print {$json_fh} '{"hosts":{"web":{"address":"127.0.0.1"}},"checks":[{"from":"local","to":"web","protocol":"tcp","port":443}]}';
close $json_fh;
my $json_config = NetSherlock::Config->load_file($json_path);
is $json_config->{checks}[0]{port}, 443, 'JSON configuration is supported';

my ( $bad_fh, $bad_path ) = tempfile();
print {$bad_fh} "hosts:\n  web:\n    address: 127.0.0.1\nchecks:\n  - from: local\n    to: web\n    protocol: udp\n    port: 53\n";
close $bad_fh;
my $error;
eval { NetSherlock::Config->load_file($bad_path) };
$error = $@;
like $error, qr/not supported|use tcp/i, 'unsupported protocol is rejected';

done_testing;

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Test::More;

use NetSherlock::Diagnose;
use NetSherlock::Result;

sub result { return NetSherlock::Result->new(@_) }

my $refused = NetSherlock::Diagnose::analyze(
    results => [
        result( check => 'dns', target => 'db.example', success => 1, status => 'success', detail => { addresses => ['10.0.0.31'] } ),
        result( check => 'tcp', target => '10.0.0.31', port => 5432, success => 0, status => 'connection_refused', error => 'Connection refused' ),
    ],
);
is $refused->{summary}, 'The destination refused the requested TCP connection.', 'refusal summary is precise';
like join(' ', @{ $refused->{facts} }), qr/refused/, 'refusal is an observed fact';
like join(' ', @{ $refused->{interpretations} }), qr/no listener|firewall/i,
  'refusal lists possibilities rather than claiming a service is down';
unlike join(' ', @{ $refused->{interpretations} }), qr/PostgreSQL is down/i,
  'diagnosis does not invent service certainty';

my $filtered_icmp = NetSherlock::Diagnose::analyze(
    results => [
        result( check => 'dns', target => 'host.example', success => 1, status => 'success', detail => { addresses => ['192.0.2.5'] } ),
        result( check => 'ping', target => 'host.example', success => 0, status => 'timeout' ),
        result( check => 'tcp', target => 'host.example', port => 443, success => 1, status => 'success' ),
    ],
);
like join(' ', @{ $filtered_icmp->{interpretations} }), qr/does not prove that the host is down/i,
  'failed ping plus successful TCP does not claim host is down';

my $dns_failure = NetSherlock::Diagnose::analyze(
    results => [ result( check => 'dns', target => 'missing.invalid', success => 0, status => 'dns_failure', error => 'NXDOMAIN' ) ],
);
is $dns_failure->{summary}, 'Name resolution failed.', 'DNS failure gets a name-resolution summary';
like $dns_failure->{next_steps}[0], qr/hostname|DNS/i, 'DNS failure suggests resolver investigation';

done_testing;

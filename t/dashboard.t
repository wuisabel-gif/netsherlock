use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Test::More;

use NetSherlock::Triage;
use NetSherlock::Dashboard;

# --- top_source_ips: display-only volume tally -----------------------------

my $recs = NetSherlock::Triage::parse_log(<<'LOG');
203.0.113.10 - - [18/Oct/2026:13:55:01 -0700] "GET /a HTTP/1.1" 200 1 "-" "UA"
203.0.113.10 - - [18/Oct/2026:13:55:02 -0700] "GET /b HTTP/1.1" 200 1 "-" "UA"
203.0.113.10 - - [18/Oct/2026:13:55:03 -0700] "GET /c HTTP/1.1" 200 1 "-" "UA"
198.51.100.9 - - [18/Oct/2026:13:55:04 -0700] "GET /d HTTP/1.1" 200 1 "-" "UA"
LOG

is $recs->[0]{ip}, '203.0.113.10', 'source address captured for display';

my $top = NetSherlock::Dashboard::top_source_ips( $recs, 5 );
is $top->[0][0], '203.0.113.10', 'busiest address ranked first';
is $top->[0][1], 3, 'its request count is tallied';
is scalar(@$top), 2, 'two distinct addresses';

is_deeply NetSherlock::Dashboard::top_source_ips( $recs, 1 ), [ [ '203.0.113.10', 3 ] ],
  'the limit is honored';

is_deeply NetSherlock::Dashboard::top_source_ips( [], 5 ), [], 'no records, no addresses';

# --- render: a readable board over a classified report --------------------

my $report = NetSherlock::Triage::classify( records => $recs );
my $board = NetSherlock::Dashboard::render(
    report  => $report,
    records => $recs,
    path    => 'test.log',
    now     => 0,
);

like $board, qr/attack dashboard/,            'board has a title';
like $board, qr/Watching:\s+test\.log/,       'board names the watched log';
like $board, qr/By category/,                 'board has the category panel';
like $board, qr/SQLi/,                        'board lists the SQLi category';
like $board, qr/Brute-force/,                 'board lists the brute-force category';
like $board, qr/normal\s+4/,                  'board counts served (normal) requests';
like $board, qr/display only, never auto-banned/, 'board states addresses are display-only';
like $board, qr/203\.0\.113\.10/,             'board shows the busiest address';

# attack traffic shows up in the recent panel
my $sqli = NetSherlock::Triage::parse_log(
    q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /p?id=1%20UNION%20SELECT%20x%20FROM%20u-- HTTP/1.1" 200 1 "-" "UA"}
);
my $sqli_board = NetSherlock::Dashboard::render(
    report => NetSherlock::Triage::classify( records => $sqli ), records => $sqli, now => 0 );
like $sqli_board, qr/SQL-injection payload/, 'a flagged request appears with its reason';

# --- CLI integration -------------------------------------------------------

my $cli    = "$Bin/../bin/netsherlock";
my $sample = "$Bin/../examples/sample-access.log";
my $out    = `$cli dashboard $sample --once`;
is $?, 256, 'dashboard exits 1 when attacks are present in the log';
like $out, qr/attack dashboard/, 'dashboard renders over the sample log';
like $out, qr/Brute-force\s+6/, 'dashboard counts the brute-force burst';

done_testing;

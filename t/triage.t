use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use JSON::PP ();
use Test::More;

use NetSherlock::Triage;

# --- parsing ---------------------------------------------------------------

my $records = NetSherlock::Triage::parse_log(<<'LOG');
203.0.113.10 - - [18/Oct/2026:13:55:01 -0700] "GET /index.html HTTP/1.1" 200 5312 "-" "Mozilla/5.0"

garbage line that is not a log entry
{"method":"GET","url":"/api?q=1","status":200,"user_agent":"app"}
LOG

is scalar(@$records), 2, 'blank and unparseable lines are skipped';
is $records->[0]{method}, 'GET', 'access-log method parsed';
is $records->[0]{path}, '/index.html', 'access-log path parsed';
is $records->[1]{source}, 'json', 'JSON record recognized';

# --- per-request content signatures ---------------------------------------

sub verdicts {
    my ($log, %opts) = @_;
    return NetSherlock::Triage::classify( records => NetSherlock::Triage::parse_log($log), %opts );
}

sub reasons_of {
    my ($result) = @_;
    return join ' | ', @{ $result->detail->{reasons} || [] };
}

my $sqli = verdicts(q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /p?id=1%20UNION%20SELECT%20pw%20FROM%20users-- HTTP/1.1" 200 1 "-" "UA"});
is $sqli->{flagged}, 1, 'SQL-injection request is flagged';
like reasons_of( $sqli->{results}[0] ), qr/SQL-injection/, 'SQLi reason reported';
cmp_ok $sqli->{results}[0]->detail->{confidence}, '>=', 0.5, 'SQLi confidence above threshold';

my $trav = verdicts(q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /d?f=../../../etc/passwd HTTP/1.1" 404 1 "-" "UA"});
like reasons_of( $trav->{results}[0] ), qr/path-traversal/, 'path traversal detected';

my $xss = verdicts(q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /c?t=<script>alert(1)</script> HTTP/1.1" 200 1 "-" "UA"});
like reasons_of( $xss->{results}[0] ), qr/cross-site scripting/, 'XSS detected';

my $scan = verdicts(q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /?p=1 HTTP/1.1" 200 1 "-" "sqlmap/1.8"});
like reasons_of( $scan->{results}[0] ), qr/scanning.attack tool/, 'scanner User-Agent detected';

my $env = verdicts(q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /.env HTTP/1.1" 404 1 "-" "curl/8"});
like reasons_of( $env->{results}[0] ), qr/sensitive path/, 'sensitive-path enumeration detected';

# --- legitimate traffic is served, not flagged ----------------------------

my $legit = verdicts(<<'LOG');
203.0.113.10 - - [18/Oct/2026:13:55:01 -0700] "GET /index.html HTTP/1.1" 200 5312 "-" "Mozilla/5.0"
203.0.113.10 - - [18/Oct/2026:13:55:02 -0700] "GET /search?q=wireless+headphones HTTP/1.1" 200 4410 "-" "Mozilla/5.0"
198.51.100.23 - - [18/Oct/2026:13:55:04 -0700] "POST /login HTTP/1.1" 200 412 "-" "MyShopApp/2.1"
LOG
is $legit->{flagged}, 0, 'ordinary requests are not flagged';
is $legit->{clean}, 3, 'all legitimate requests are served';

# --- behavioral: auth brute-force (grouped by endpoint, not by IP) ---------

my $brute_log = join "\n",
  map { sprintf '198.51.100.%d - - [18/Oct/2026:13:55:%02d -0700] "POST /login HTTP/1.1" 401 56 "-" "x"', $_ + 20, $_ + 20 } ( 1 .. 6 );
my $brute = verdicts( $brute_log, fails => 5 );
is $brute->{flagged}, 6, 'all failed-login requests in the burst are flagged (distinct IPs)';
like reasons_of( $brute->{results}[0] ), qr/brute-force: 6 failed/, 'brute-force counts failures per endpoint';

# four failures is below the default threshold and must stay served
my $few = verdicts( join( "\n", (split /\n/, $brute_log)[0..3] ), fails => 5 );
is $few->{flagged}, 0, 'a few failed logins are not brute-force';

# --- behavioral: abnormal request rate ------------------------------------

my $burst = join "\n",
  map { sprintf '9.9.9.9 - - [18/Oct/2026:14:00:%02d -0700] "GET /api/x HTTP/1.1" 200 1 "-" "UA"', $_ } ( 1 .. 8 );
my $rate = verdicts( $burst, window => 10, rate => 5 );
is $rate->{flagged}, 8, 'a burst over the rate limit is flagged';
like reasons_of( $rate->{results}[0] ), qr/abnormal request rate/, 'rate anomaly reason reported';

# --- CLI integration on the committed sample -------------------------------

my $cli = "$Bin/../bin/netsherlock";
my $sample = "$Bin/../examples/sample-access.log";
my $json = `$cli triage $sample --json`;
is $?, 256, 'triage exits 1 when attacks are observed';
my $doc = eval { JSON::PP::decode_json($json) };
ok $doc, 'triage JSON parses';
cmp_ok $doc->{summary}{flagged}, '>=', 6, 'sample log flags the expected attacks';
cmp_ok $doc->{summary}{clean}, '>', 0, 'sample log still serves legitimate requests';
ok $doc->{summary}{categories}{sql_injection}, 'sample log detects SQL injection';
ok $doc->{summary}{categories}{brute_force}, 'sample log detects brute-force';

my $missing = `$cli triage /no/such/log 2>&1`;
is $?, 512, 'missing log file is a usage/configuration error';

done_testing;

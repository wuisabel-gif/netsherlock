use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Test::More;

use NetSherlock::Triage;
use NetSherlock::Alert;

# A real flagged result to shape alerts from.
sub flagged {
    my ($log) = @_;
    my $report = NetSherlock::Triage::classify( records => NetSherlock::Triage::parse_log($log) );
    return $report->{results}[0];
}

my $sqli = flagged(
    q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /p?id=1%20UNION%20SELECT%20x%20FROM%20u-- HTTP/1.1" 200 1 "-" "UA"}
);

# --- message + payload shaping --------------------------------------------

my $a = NetSherlock::Alert->new( dry_run => 1 );
like $a->message_for($sqli), qr/confidence 0\.80/, 'message carries the confidence';
like $a->message_for($sqli), qr{GET /p},           'message carries method and path';
like $a->message_for($sqli), qr/SQL-injection/,    'message carries the reason';

# Slack shape by default; Discord inferred from the webhook host; explicit wins.
is_deeply [ sort keys %{ NetSherlock::Alert->new->payload_for($sqli) } ], ['text'],
  'default (auto, no URL) uses the Slack {text} shape';
is_deeply
  [ sort keys %{ NetSherlock::Alert->new( url => 'https://discord.com/api/webhooks/1/abc' )->payload_for($sqli) } ],
  ['content'], 'a discord.com webhook infers the {content} shape';
is_deeply
  [ sort keys %{ NetSherlock::Alert->new( url => 'https://hooks.slack.com/services/x' )->payload_for($sqli) } ],
  ['text'], 'a hooks.slack.com webhook infers the {text} shape';
is_deeply [ sort keys %{ NetSherlock::Alert->new( format => 'discord' )->payload_for($sqli) } ], ['content'],
  'an explicit --webhook-format overrides inference';

# --- debounce: one scan is not five hundred alerts -------------------------

my $d = NetSherlock::Alert->new( debounce => 60, dry_run => 1 );
ok $d->should_send( $sqli, 1000 ),  'first alert for a category+path is sent';
ok !$d->should_send( $sqli, 1030 ), 'a repeat within the window is suppressed';
ok $d->should_send( $sqli, 1070 ),  'after the window it is sent again';

# a different path is a different bucket and is not suppressed
my $trav = flagged(
    q{1.1.1.1 - - [18/Oct/2026:13:55:09 -0700] "GET /d?f=../../../etc/passwd HTTP/1.1" 404 1 "-" "UA"}
);
ok $d->should_send( $trav, 1030 ), 'a different path alerts even within the window';

# --- dry-run delivers a payload without posting ----------------------------

my $out = NetSherlock::Alert->new( dry_run => 1 )->deliver($sqli);
ok $out->{dry_run}, 'dry-run is reported';
ok !$out->{sent},   'dry-run sends nothing';
ok $out->{payload}{text}, 'dry-run still returns the payload to preview';

# --- CLI integration: sample log, dry-run, debounced -----------------------

my $cli    = "$Bin/../bin/netsherlock";
my $sample = "$Bin/../examples/sample-access.log";
my $cli_out = `$cli alert $sample --dry-run --once --from-start`;
is $?, 0, 'alert --dry-run exits 0';
like $cli_out, qr/\[dry-run\] would POST/, 'dry-run prints what it would send';
like $cli_out, qr/SQL-injection/,          'the SQLi attack is alerted';

# the six-request brute-force burst collapses to one alert (debounced)
my $logins = () = $cli_out =~ /auth brute-force/g;
is $logins, 1, 'the brute-force burst is debounced to a single alert';

# live sending refuses without a webhook
my $refuse = `$cli alert $sample --no-dry-run --once 2>&1`;
isnt $?, 0, 'live alerting without a webhook is refused';
like $refuse, qr/webhook/, 'the refusal explains a webhook is required';

done_testing;

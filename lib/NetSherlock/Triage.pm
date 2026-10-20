package NetSherlock::Triage;

use strict;
use warnings;

use Time::Local ();

use NetSherlock::Result;

=head1 NAME

NetSherlock::Triage - flag likely attack traffic by request behavior

=head1 DESCRIPTION

Ingests request records - Apache/nginx access-log lines or generic
JSON-per-line records - and classifies each as likely attack traffic or
not. Classification is content- and behavior-based and never keyed on the
source IP: attackers alias many addresses and legitimate and hostile IPs
look identical, so an address proves nothing about intent.

Two kinds of signal are combined:

    per-request content  SQL injection, path traversal, XSS, command
                         injection, sensitive-path enumeration, and known
                         scanner User-Agents.

    aggregate behavior   auth brute-force (many failed authentications
                         against one endpoint) and abnormal request rate
                         (a burst of requests to one path in a short
                         window). Both are grouped by target resource, not
                         by client address.

Each flagged request becomes a NetSherlock::Result (check => 'request',
status => 'attack') carrying its reasons and a 0..1 confidence score, so
the existing Reporter and JSON output render it unchanged. Legitimate
requests are not reported - they are served.

=cut

# ponytail: calibration knobs. The real world needs tuning a fixed model
# cannot see (traffic shape differs per site), so these are overridable from
# the CLI (--window/--rate/--fails) and the threshold is a package default.
our $DEFAULT_WINDOW = 10;    # seconds per rate/brute bucket
our $DEFAULT_RATE   = 20;    # requests per window per path before "abnormal"
our $DEFAULT_FAILS  = 5;     # failed auths per window per path before "brute"
our $THRESHOLD      = 0.5;   # confidence at or above which a request is flagged

# [ category, weight, qr//, field ]  field: 'uri' (path+query) or 'ua'.
# Weights sum per request and cap at 1.0. A lone high-signal hit (>= 0.5)
# flags; weaker hints only matter in combination.
my @CONTENT_SIGNATURES = (
    [ 'sql_injection', 0.8,
      qr/(?:\bunion\b[\s\S]*?\bselect\b|\bselect\b[\s\S]*?\bfrom\b|\bor\b\s+1\s*=\s*1|'\s*or\s*'|\bor\b\s+'[^']*'\s*=\s*'|--\s|;\s*--|\/\*.*\*\/|\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\binformation_schema\b|\bload_file\s*\(|\bextractvalue\s*\()/i,
      'uri' ],
    [ 'path_traversal', 0.8,
      qr/(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c|\/|\\)|%252e%252e|\/etc\/passwd\b|\/proc\/self\/|\bboot\.ini\b|\bwin\.ini\b)/i,
      'uri' ],
    [ 'xss', 0.7,
      qr/(?:<script\b|%3cscript|onerror\s*=|onload\s*=|onmouseover\s*=|javascript:|<svg\b|<img[^>]+onerror|document\.cookie)/i,
      'uri' ],
    [ 'command_injection', 0.8,
      qr/(?:;\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b|\|\s*(?:cat|sh|bash|nc)\b|\$\([^)]+\)|`[^`]+`|&&\s*(?:cat|id|whoami)\b)/i,
      'uri' ],
    [ 'sensitive_path', 0.5,
      qr/(?:\/\.env\b|\/\.git(?:\/|\b)|\/\.aws\b|\/\.ssh\b|\/wp-login\.php|\/wp-admin\b|\/phpmyadmin\b|\/xmlrpc\.php|\/cgi-bin\/|\/\.htpasswd\b|\/backup\b|\/shell\b|\/config\.(?:php|json|yml))/i,
      'uri' ],
    # Known offensive tools only; generic clients (curl, python-requests) are
    # NOT here - flagging them would drop legitimate automation.
    [ 'scanner_tool', 0.7,
      qr/(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|nessus|acunetix|havij|fimap|whatweb|zgrab|arachni|wfuzz|nuclei)/i,
      'ua' ],
);

my %REASON = (
    sql_injection     => 'SQL-injection payload in request',
    path_traversal    => 'path-traversal sequence in request',
    xss               => 'cross-site scripting probe in request',
    command_injection => 'command-injection pattern in request',
    sensitive_path    => 'enumeration of a sensitive path',
    scanner_tool      => 'known scanning/attack tool in User-Agent',
);

# Bounded, possibility-phrased explanations, matching NetSherlock's habit of
# not overstating what evidence proves.
my %INTERPRETATION = (
    sql_injection     => 'A request carried syntax characteristic of SQL injection. This indicates a probe or exploit attempt against a database-backed endpoint, independent of its source address.',
    path_traversal    => 'A request contained directory-traversal sequences, consistent with an attempt to read files outside the web root.',
    xss               => 'A request carried script-injection markup, consistent with a reflected or stored XSS probe.',
    command_injection => 'A request contained shell metacharacters and command names, consistent with an OS command-injection attempt.',
    sensitive_path    => 'One or more requests targeted paths that expose secrets or admin surfaces, consistent with enumeration rather than normal use.',
    scanner_tool      => 'A request advertised a known scanning or exploitation tool in its User-Agent. A User-Agent is self-reported and easily forged, so treat it as a hint, not proof.',
    brute_force       => 'Repeated authentication failures against a single endpoint are consistent with credential brute-forcing. This is counted per target endpoint, not per source address.',
    rate_anomaly      => 'A burst of requests to one path within a short window is consistent with automated enumeration or flooding, not interactive use.',
);

my %MONTH = (
    Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4,  Jun => 5,
    Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11,
);

=head2 parse_log($text)

Parse a block of log text into an arrayref of request records. Combined/
common access-log lines and JSON-per-line records are both accepted;
blank lines and unparseable lines are skipped. The returned records are
plain hashrefs with keys: line, method, uri, path, query, status, ua, ts
(epoch or undef), auth_failed, source.

=cut

sub parse_log {
    my ($text) = @_;
    $text = '' unless defined $text;
    my @records;
    my $line_no = 0;

    for my $line ( split /\r?\n/, $text ) {
        $line_no++;
        next if $line =~ /^\s*$/;
        my $rec = ( $line =~ /^\s*\{/ ) ? _parse_json_record($line) : _parse_access_line($line);
        next unless $rec;
        $rec->{line} = $line_no;
        push @records, $rec;
    }

    return \@records;
}

# "ip - - [time] \"METHOD uri proto\" status size \"ref\" \"ua\""
my $ACCESS_RE = qr/
    ^(\S+)\s+\S+\s+\S+\s+              # ip ident authuser (ignored; never IP-keyed)
    \[([^\]]+)\]\s+                    # [time]
    "([A-Z]+)\s+(\S+)(?:\s+(\S+))?"\s+ # "METHOD uri proto"
    (\d{3})\s+(\S+)                    # status size
    (?:\s+"([^"]*)"\s+"([^"]*)")?      # "referer" "user-agent"
/x;

sub _parse_access_line {
    my ($line) = @_;
    return undef unless $line =~ $ACCESS_RE;
    my ( $ip, $time, $method, $uri, undef, $status, undef, undef, $ua ) =
      ( $1, $2, $3, $4, $5, $6, $7, $8, $9 );
    my ( $path, $query ) = split /\?/, $uri, 2;
    return {
        source      => 'access_log',
        method      => $method,
        uri         => $uri,
        path        => $path,
        query       => $query,
        status      => $status + 0,
        ua          => defined $ua ? $ua : '',
        ts          => _parse_apache_time($time),
        auth_failed => 0,
    };
}

sub _parse_json_record {
    my ($line) = @_;
    require JSON::PP;
    my $obj = eval { JSON::PP::decode_json($line) };
    return undef unless ref($obj) eq 'HASH';

    my $uri    = _first( $obj, qw(uri url path request request_uri) );
    $uri = '/' unless defined $uri && length $uri;
    my $method = _first( $obj, qw(method verb) ) // 'GET';
    my $query  = _first( $obj, qw(query query_string) );
    if ( !defined $query && $uri =~ /\?/ ) {
        ( undef, $query ) = split /\?/, $uri, 2;
    }
    my ( $path ) = split /\?/, $uri, 2;
    if ( defined $query && length $query && $uri !~ /\?/ ) {
        $uri .= '?' . $query;    # fold a separate query field back onto the uri for content scanning
    }
    my $status = _first( $obj, qw(status status_code code) );
    my $ua     = _first( $obj, qw(ua user_agent agent useragent) ) // '';
    my $ts     = _first( $obj, qw(ts time timestamp epoch) );
    my $failed = _first( $obj, qw(auth_failed failed_login login_failed) );

    return {
        source      => 'json',
        method      => uc $method,
        uri         => $uri,
        path        => $path,
        query       => $query,
        status      => defined $status ? $status + 0 : undef,
        ua          => $ua,
        ts          => _parse_ts($ts),
        auth_failed => $failed ? 1 : 0,
    };
}

sub _first {
    my ( $obj, @keys ) = @_;
    for my $k (@keys) {
        return $obj->{$k} if defined $obj->{$k};
    }
    return undef;
}

# "10/Oct/2026:13:55:36 -0700" -> epoch (tz offset ignored; good enough for
# windowing). Returns undef if unparseable.
sub _parse_apache_time {
    my ($s) = @_;
    return undef unless defined $s
      && $s =~ m{^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})};
    my $mon = $MONTH{$2};
    return undef unless defined $mon;
    return eval { Time::Local::timegm( $6, $5, $4, $1, $mon, $3 - 1900 ) };
}

sub _parse_ts {
    my ($v) = @_;
    return undef unless defined $v;
    return $v + 0 if $v =~ /^\d+(?:\.\d+)?$/;    # epoch seconds
    # ISO 8601: 2026-10-10T13:55:36 (tz ignored)
    if ( $v =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/ ) {
        return eval { Time::Local::timegm( $6, $5, $4, $3, $2 - 1, $1 - 1900 ) };
    }
    return _parse_apache_time($v);
}

=head2 classify(records => \@records, window => $s, rate => $n, fails => $n)

Score every record and return a report hashref:

    {
        results    => [ NetSherlock::Result, ... ],  # flagged requests only
        total      => $count_in,
        flagged    => $count_flagged,
        clean      => $count_served,
        categories => { $category => $count, ... },
    }

=cut

sub classify {
    my (%args) = @_;
    my $records = $args{records} || [];
    die 'NetSherlock::Triage::classify requires an arrayref of records'
      unless ref($records) eq 'ARRAY';

    my $window = defined $args{window} ? $args{window} : $DEFAULT_WINDOW;
    my $rate   = defined $args{rate}   ? $args{rate}   : $DEFAULT_RATE;
    my $fails  = defined $args{fails}  ? $args{fails}  : $DEFAULT_FAILS;

    # One scoring accumulator per record: category => weight.
    my @scores = map { {} } @$records;

    _score_content( $records, \@scores );
    _score_brute_force( $records, \@scores, $window, $fails );
    _score_rate( $records, \@scores, $window, $rate );

    my @results;
    my ( $flagged, %categories ) = (0);

    for my $i ( 0 .. $#$records ) {
        my $score = $scores[$i];
        next unless %$score;

        my $confidence = 0;
        $confidence += $score->{$_} for grep { !/\.reason$/ } keys %$score;
        $confidence = 1 if $confidence > 1;
        next if $confidence < $THRESHOLD;

        my $rec = $records->[$i];
        # Reasons in a stable order: strongest category first.
        my @cats = sort { $score->{$b} <=> $score->{$a} || $a cmp $b }
          grep { !/\.reason$/ } keys %$score;
        my @reasons = map { $score->{"$_.reason"} || $REASON{$_} || $_ } @cats;
        $categories{$_}++ for @cats;
        $flagged++;

        push @results,
          NetSherlock::Result->new(
            check   => 'request',
            target  => $rec->{path},
            success => 0,
            status  => 'attack',
            detail  => {
                method      => $rec->{method},
                path        => $rec->{path},
                line        => $rec->{line},
                source      => $rec->{source},
                status_code => $rec->{status},
                confidence  => sprintf( '%.2f', $confidence ) + 0,
                reasons     => \@reasons,
                categories  => \@cats,
            },
          );
    }

    return {
        results    => \@results,
        total      => scalar(@$records),
        flagged    => $flagged,
        clean      => scalar(@$records) - $flagged,
        categories => \%categories,
    };
}

sub _score_content {
    my ( $records, $scores ) = @_;
    for my $i ( 0 .. $#$records ) {
        my $rec = $records->[$i];
        my $uri = defined $rec->{uri} ? $rec->{uri} : '';
        my $hay = $uri . ' ' . _urldecode($uri);
        my $ua  = defined $rec->{ua} ? $rec->{ua} : '';

        for my $sig (@CONTENT_SIGNATURES) {
            my ( $cat, $weight, $re, $field ) = @$sig;
            my $subject = $field eq 'ua' ? $ua : $hay;
            $scores->[$i]{$cat} = $weight if $subject =~ $re;
        }
    }
}

# Many failed authentications against ONE endpoint (grouped by path + time
# window), regardless of source address.
sub _score_brute_force {
    my ( $records, $scores, $window, $fails ) = @_;
    my %bucket;    # "path\0win" => [ indices ]
    for my $i ( 0 .. $#$records ) {
        my $rec = $records->[$i];
        next unless _is_auth_failure($rec);
        my $key = _bucket_key( $rec, $window );
        push @{ $bucket{$key} }, $i;
    }
    for my $key ( keys %bucket ) {
        my $idx = $bucket{$key};
        next if @$idx < $fails;
        my ($path) = split /\0/, $key;
        my $reason = sprintf( 'auth brute-force: %d failed attempt(s) against %s', scalar(@$idx), $path );
        for my $i (@$idx) {
            $scores->[$i]{brute_force}          = 0.7;
            $scores->[$i]{'brute_force.reason'} = $reason;
        }
    }
}

# A burst of requests to one path within a window - automated, not interactive.
sub _score_rate {
    my ( $records, $scores, $window, $rate ) = @_;
    my %bucket;
    for my $i ( 0 .. $#$records ) {
        my $rec = $records->[$i];
        next unless defined $rec->{ts};    # ponytail: no timestamp, no rate signal
        push @{ $bucket{ _bucket_key( $rec, $window ) } }, $i;
    }
    for my $key ( keys %bucket ) {
        my $idx = $bucket{$key};
        next if @$idx <= $rate;
        my ($path) = split /\0/, $key;
        my $reason = sprintf( 'abnormal request rate: %d request(s) in %gs to %s', scalar(@$idx), $window, $path );
        for my $i (@$idx) {
            $scores->[$i]{rate_anomaly}          = 0.5;
            $scores->[$i]{'rate_anomaly.reason'} = $reason;
        }
    }
}

sub _is_auth_failure {
    my ($rec) = @_;
    return 1 if $rec->{auth_failed};
    my $s = $rec->{status};
    return 0 unless defined $s;
    return 1 if $s == 401 || $s == 403;
    # A 200/302 on a login endpoint is a successful login, so only count
    # explicit rejections on auth-ish paths plus rate limiting.
    return 1 if $s == 429 && ( $rec->{path} // '' ) =~ m{/(?:login|signin|sign-in|auth|session|token|oauth)}i;
    return 0;
}

sub _bucket_key {
    my ( $rec, $window ) = @_;
    my $path = defined $rec->{path} ? $rec->{path} : '';
    my $win  = defined $rec->{ts}   ? int( $rec->{ts} / $window ) : 'na';
    return "$path\0$win";
}

sub _urldecode {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
    return $s;
}

=head2 interpretations_for(\%categories)

Return an arrayref of bounded explanations for the categories present, in
a stable order. Used by the CLI to build the diagnosis block.

=cut

sub interpretations_for {
    my ($categories) = @_;
    my @order = qw(sql_injection command_injection path_traversal xss sensitive_path scanner_tool brute_force rate_anomaly);
    return [ map { $INTERPRETATION{$_} } grep { $categories->{$_} } @order ];
}

1;

package NetSherlock::Dashboard;

use strict;
use warnings;

=head1 NAME

NetSherlock::Dashboard - terminal attack-detection dashboard

=head1 DESCRIPTION

Formats the output of L<NetSherlock::Triage/classify> as a compact,
refreshable text board: request counts by category, the most recent
flagged requests with their reason and confidence, and the busiest source
addresses by request volume.

Like L<NetSherlock::Reporter>, this module only formats supplied data - it
reads no files and opens no sockets, so it is driven on an interval by the
CLI and tested directly.

The source-address panel is informational only. NetSherlock never bans or
scores a client by address: scanners, scoring services and legitimate users
share the same networks, so volume ranks the noisiest callers, nothing more.

=cut

# Internal category key -> display label, in a stable display order. Rows are
# always shown (even at zero) so a live board does not jump around as traffic
# shifts; "normal" is appended from the served (clean) count.
my @CATEGORY_ORDER = (
    [ sql_injection     => 'SQLi' ],
    [ command_injection => 'Command-injection' ],
    [ path_traversal    => 'Path-traversal' ],
    [ xss               => 'XSS' ],
    [ sensitive_path    => 'Sensitive-path' ],
    [ scanner_tool      => 'Scanner' ],
    [ brute_force       => 'Brute-force' ],
    [ rate_anomaly      => 'Rate-anomaly' ],
);

=head2 top_source_ips($records, $limit)

Tally request volume per source address and return an arrayref of
C<[ $ip, $count ]> pairs, busiest first, at most C<$limit> entries.
Records without an address are ignored.

=cut

sub top_source_ips {
    my ( $records, $limit ) = @_;
    $limit = 5 unless defined $limit;
    my %count;
    for my $rec (@$records) {
        my $ip = $rec->{ip};
        next unless defined $ip && length $ip;
        $count{$ip}++;
    }
    my @ranked = sort { $count{$b} <=> $count{$a} || $a cmp $b } keys %count;
    splice @ranked, $limit if @ranked > $limit;    # don't slice past the end
    return [ map { [ $_, $count{$_} ] } @ranked ];
}

=head2 render(report => $report, records => $records, %opts)

Return the dashboard as a string (no terminal control codes; the caller
clears the screen and redraws on its own interval). Options: C<path> (the
log being watched), C<now> (epoch for the header, defaults to time()),
C<recent> (how many flagged requests to list, default 8), C<top> (how many
source addresses to list, default 5).

=cut

sub render {
    my (%args) = @_;
    my $report  = $args{report}  || {};
    my $records = $args{records} || [];
    my $recent  = defined $args{recent} ? $args{recent} : 8;
    my $top     = defined $args{top}    ? $args{top}    : 5;
    my $now     = defined $args{now}    ? $args{now}    : time();

    my $cats  = $report->{categories} || {};
    my $total = $report->{total}   || 0;
    my $flag  = $report->{flagged} || 0;
    my $clean = $report->{clean}   || 0;

    my @lines;
    push @lines, 'NetSherlock attack dashboard';
    push @lines, sprintf( 'Watching: %s', $args{path} // '(stdin)' );
    push @lines, sprintf( 'Updated:  %s   requests: %d   flagged: %d   served: %d',
        _stamp($now), $total, $flag, $clean );
    push @lines, '';

    # --- counts by category --------------------------------------------------
    push @lines, 'By category';
    for my $pair ( @CATEGORY_ORDER ) {
        my ( $key, $label ) = @$pair;
        push @lines, sprintf( '  %-18s %5d  %s', $label, $cats->{$key} || 0, _bar( $cats->{$key} || 0 ) );
    }
    push @lines, sprintf( '  %-18s %5d  %s', 'normal', $clean, _bar($clean) );
    push @lines, '';

    # --- most recent flagged requests ---------------------------------------
    push @lines, sprintf( 'Recent flagged (newest %d)', $recent );
    my @results = @{ $report->{results} || [] };
    if (@results) {
        # classify() preserves input order, so the tail is the most recent.
        my @tail = @results > $recent ? @results[ -$recent .. -1 ] : @results;
        for my $r ( reverse @tail ) {
            my $d = $r->detail || {};
            my $reason = ( $d->{reasons} && @{ $d->{reasons} } ) ? $d->{reasons}[0] : $r->status;
            push @lines, sprintf(
                '  %.2f  %-4s %-28s %s',
                ( $d->{confidence} || 0 ),
                ( $d->{method} || '?' ),
                _clip( $d->{path} // $r->target // '', 28 ),
                _clip( $reason, 48 ),
            );
        }
    }
    else {
        push @lines, '  (no attack traffic flagged yet)';
    }
    push @lines, '';

    # --- top source addresses (display only) --------------------------------
    push @lines, sprintf( 'Top source addresses by volume (display only, never auto-banned)' );
    my $ips = top_source_ips( $records, $top );
    if (@$ips) {
        push @lines, sprintf( '  %-24s %s', $_->[0], _bar( $_->[1] ) . ' ' . $_->[1] ) for @$ips;
    }
    else {
        push @lines, '  (no addressed requests)';
    }

    return join( "\n", @lines ) . "\n";
}

# A tiny proportional bar. ponytail: fixed 1-unit-per-request up to 30, good
# enough to eyeball relative volume on one screen; no scaling pass.
sub _bar {
    my ($n) = @_;
    $n = 0 if !$n || $n < 0;
    $n = 30 if $n > 30;
    return '#' x $n;
}

sub _clip {
    my ( $s, $max ) = @_;
    $s = '' unless defined $s;
    return $s if length $s <= $max;
    return substr( $s, 0, $max - 1 ) . '~';
}

sub _stamp {
    my ($epoch) = @_;
    my @t = localtime($epoch);
    return sprintf( '%04d-%02d-%02d %02d:%02d:%02d',
        $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0] );
}

1;

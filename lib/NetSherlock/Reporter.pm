package NetSherlock::Reporter;

use strict;
use warnings;

use JSON::PP ();

=head1 NAME

NetSherlock::Reporter - human and JSON presentation of evidence

=head1 DESCRIPTION

The reporter only formats supplied results and diagnosis. It never opens
sockets, resolves names, or invokes commands.

=cut

sub human {
    my (%args) = @_;
    my $title     = $args{title} // 'NetSherlock';
    my $target    = $args{target};
    my $results   = $args{results} || [];
    my $groups    = $args{groups} || [];
    my $diagnosis = $args{diagnosis} || {};
    my $quiet     = $args{quiet} ? 1 : 0;

    my @lines;
    push @lines, $title;
    push @lines, "Target: $target" if defined $target && length $target;

    if ( !$quiet && @$groups ) {
        for my $group (@$groups) {
            push @lines, "Check: " . $group->{name};
            for my $result ( @{ $group->{results} || [] } ) {
                push @lines, _result_line($result);
                push @lines, _detail_lines($result);
            }
        }
    }
    elsif (!$quiet) {
        for my $result (@$results) {
            push @lines, _result_line($result);
            push @lines, _detail_lines($result);
        }
    }

    if ( defined $diagnosis->{summary} && length $diagnosis->{summary} ) {
        push @lines, 'Diagnosis:';
        push @lines, '  ' . $diagnosis->{summary};
    }

    if ( !$quiet && @{ $diagnosis->{facts} || [] } ) {
        push @lines, 'Observed:';
        push @lines, map { '  ' . $_ } @{ $diagnosis->{facts} };
    }

    if ( !$quiet && @{ $diagnosis->{interpretations} || [] } ) {
        push @lines, $diagnosis->{has_failure} ? 'Possible explanations:' : 'Interpretation:';
        my $number = 1;
        push @lines, map { '  ' . $number++ . '. ' . $_ } @{ $diagnosis->{interpretations} };
    }

    if ( !$quiet && @{ $diagnosis->{next_steps} || [] } ) {
        push @lines, 'Investigate next:';
        push @lines, map { '  - ' . $_ } @{ $diagnosis->{next_steps} };
    }

    return join( "\n", @lines ) . "\n";
}

sub json {
    my (%args) = @_;
    my $results   = $args{results} || [];
    my $diagnosis = $args{diagnosis} || {};
    my $extra     = $args{extra} || {};

    my %document = (
        tool      => 'NetSherlock',
        version   => ( eval { require NetSherlock; $NetSherlock::VERSION } || 'unknown' ),
        results   => [ map { $_->to_hash } @$results ],
        diagnosis => $diagnosis,
        %$extra,
    );

    return JSON::PP->new->canonical->pretty->encode(\%document);
}

sub _result_line {
    my ($result) = @_;
    my $mark = $result->success ? '[OK]' : '[FAIL]';
    my %labels = ( dns => 'DNS', ping => 'Ping', tcp => 'TCP', trace => 'Trace' );
    my $label = $result->check eq 'tcp'
      ? 'TCP/' . ( $result->port // '' )
      : ( $labels{ $result->check } || ucfirst( $result->check ) );
    my $subject = defined $result->target ? ' ' . $result->target : '';
    my $suffix = $result->success ? $result->status : $result->status;
    $suffix .= sprintf( ' (%.1f ms)', $result->latency_ms ) if defined $result->latency_ms;
    return "$mark $label$subject: $suffix";
}

sub _detail_lines {
    my ($result) = @_;
    my @lines;
    my $detail = $result->detail || {};

    if ( $result->check eq 'dns' && ref( $detail->{addresses} ) eq 'ARRAY' ) {
        push @lines, map { '    ' . $_ } @{ $detail->{addresses} };
    }
    elsif ( $result->check eq 'trace' && ref( $detail->{hops} ) eq 'ARRAY' ) {
        for my $hop ( @{ $detail->{hops} } ) {
            my $where = @{ $hop->{addresses} || [] } ? join( ', ', @{ $hop->{addresses} } ) : '*';
            my $rtt   = @{ $hop->{rtts_ms} || [] } ? sprintf( ' (%.1f ms)', $hop->{rtts_ms}[0] ) : '';
            push @lines, sprintf( '    %d  %s%s', $hop->{hop}, $where, $rtt );
        }
    }

    return @lines;
}

1;

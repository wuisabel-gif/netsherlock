package NetSherlock::Trace;

use strict;
use warnings;

use IPC::Open3 ();
use File::Spec ();
use Symbol   qw(gensym);
use Time::HiRes ();

use NetSherlock::Result;

=head1 NAME

NetSherlock::Trace - route evidence via the system traceroute

=head1 DESCRIPTION

Runs the system C<traceroute> binary with numeric output, one probe per
hop and a hard overall timeout. The binary is invoked with an argument
list (no shell), and hostnames beginning with '-' are rejected by the
CLI, so no option injection is possible.

Parsing is separated from execution so it can be unit-tested with
fixtures.

=cut

sub find_traceroute {
    for my $dir ( File::Spec->path, '/usr/sbin', '/sbin', '/usr/local/sbin' ) {
        my $candidate = File::Spec->catfile( $dir, 'traceroute' );
        return $candidate if -x $candidate;
    }
    return undef;
}

# Parse traceroute -n output into a list of hop hashrefs.
sub parse_output {
    my ($text) = @_;
    $text = '' unless defined $text;

    my @hops;
    for my $line ( split /\r?\n/, $text ) {
        next unless $line =~ /^\s*(\d+)\s+(.*)$/;
        my ( $number, $rest ) = ( $1, $2 );

        my @addresses = $rest =~ /(?<![\w:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]*[0-9A-Fa-f])(?![\w:])/g;
        my @rtts      = $rest =~ /(\d+(?:\.\d+)?)\s*ms/g;

        push @hops,
          {
            hop         => 0 + $number,
            addresses   => \@addresses,
            rtts_ms     => [ map { 0 + $_ } @rtts ],
            no_response => ( $rest =~ /\*/ && !@addresses ) ? 1 : 0,
          };
    }

    return \@hops;
}

# check(host => $host, timeout => $s, max_hops => $n, logger => $coderef)
sub check {
    my (%args) = @_;

    my $host = $args{host};
    die 'NetSherlock::Trace::check requires a host' unless defined $host;
    my $display_target = $args{display_target} // $host;
    my $expected       = $args{expected_address} // $host;

    my $timeout  = $args{timeout}  // 30;
    my $max_hops = $args{max_hops} // 30;
    my $logger   = $args{logger};

    if ( $host =~ /^-/ || $host =~ /[\0\r\n]/ ) {
        return NetSherlock::Result->new(
            check   => 'trace',
            target  => $display_target,
            success => 0,
            status  => 'unknown',
            error   => 'trace target contains invalid characters',
        );
    }
    if ( $timeout !~ /^\d+(?:\.\d+)?$/ || $timeout <= 0
        || $max_hops !~ /^\d+$/ || $max_hops < 1 ) {
        return NetSherlock::Result->new(
            check   => 'trace',
            target  => $display_target,
            success => 0,
            status  => 'unknown',
            error   => 'trace timeout and max_hops must be positive values',
        );
    }

    my $binary = find_traceroute();
    if ( !$binary ) {
        return NetSherlock::Result->new(
            check   => 'trace',
            target  => $display_target,
            success => 0,
            status  => 'unknown',
            error   => 'no traceroute binary found on this system',
        );
    }

    my @command = ( $binary, '-n', '-w', '2', '-q', '1', '-m', $max_hops, $host );
    $logger->( 'running: ' . join ' ', @command ) if $logger;

    my ( $in, $out, $err );
    $err = gensym;

    my $pid = eval { IPC::Open3::open3( $in, $out, $err, @command ) };
    if ( !$pid ) {
        my $msg = $@ || 'unknown error';
        chomp $msg;
        return NetSherlock::Result->new(
            check   => 'trace',
            target  => $display_target,
            success => 0,
            status  => 'unknown',
            error   => "failed to run traceroute: $msg",
        );
    }

    close $in;

    my ( $text, $errtext ) = ( '', '' );
    my $timed_out = 0;

    eval {
        local $SIG{ALRM} = sub { die "trace timeout\n" };
        Time::HiRes::alarm($timeout);
        while ( my $line = <$out> ) { $text    .= $line }
        while ( my $line = <$err> ) { $errtext .= $line }
        Time::HiRes::alarm(0);
    };
    if ($@) {
        $timed_out = 1;
        kill 'KILL', $pid;
    }
    waitpid $pid, 0;
    Time::HiRes::alarm(0);
    chomp $errtext;

    my $hops = parse_output($text);

    my $reached = 0;
    if (@$hops) {
        my %last = map { $_ => 1 } @{ $hops->[-1]{addresses} };
        $reached = 1 if $last{$expected};
    }

    my %base = (
        check  => 'trace',
        target => $display_target,
        detail => {
            hops    => $hops,
            reached => $reached,
            binary  => $binary,
        },
    );

    if ($timed_out) {
        return NetSherlock::Result->new(
            %base,
            success => 0,
            status  => 'timeout',
            error   => "traceroute exceeded the ${timeout}s limit",
        );
    }

    if ( !@$hops ) {
        return NetSherlock::Result->new(
            %base,
            success => 0,
            status  => 'unknown',
            error   => ( $errtext || 'traceroute produced no hops' ),
        );
    }

    if ($reached) {
        return NetSherlock::Result->new( %base, success => 1, status => 'success' );
    }

    return NetSherlock::Result->new(
        %base,
        success => 0,
        status  => 'timeout',
        error   => "did not reach $host after " . scalar(@$hops) . ' hops',
    );
}

1;

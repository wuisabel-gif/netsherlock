package NetSherlock::Diagnose;

use strict;
use warnings;

=head1 NAME

NetSherlock::Diagnose - evidence-driven interpretations

=head1 DESCRIPTION

Turns structured NetSherlock::Result objects into facts, bounded
interpretations, and investigation suggestions. This module never parses
human-readable output and never performs network operations.

An interpretation is deliberately phrased as a possibility. A refused
TCP connection is evidence that the destination answered with a refusal;
it is not proof of which service configuration caused that refusal.

=cut

sub analyze {
    my (%args) = @_;
    my $results = $args{results} || [];
    die 'NetSherlock::Diagnose::analyze requires an arrayref of results'
      unless ref($results) eq 'ARRAY';

    my @facts;
    my @interpretations;
    my @next_steps;
    my $has_failure = 0;

    for my $result (@$results) {
        next unless $result;
        my $fact = _fact_for($result);
        push @facts, $fact if defined $fact;
        $has_failure = 1 unless $result->success;
    }

    my ($dns)  = grep { $_ && $_->check eq 'dns'  } @$results;
    my ($ping) = grep { $_ && $_->check eq 'ping' } @$results;
    my ($tcp)  = grep { $_ && $_->check eq 'tcp'  } @$results;
    my ($trace) = grep { $_ && $_->check eq 'trace' } @$results;

    if ($dns && !$dns->success) {
        push @interpretations,
          'The hostname could not be resolved, so NetSherlock could not identify the destination address.';
        push @next_steps,
          'Check the hostname spelling and the host\'s DNS configuration or resolver availability.';
    }
    elsif ($dns && $dns->success && !$tcp && !$ping && !$trace) {
        push @next_steps, 'Continue investigating the route, host reachability, or service result.';
    }

    if ($tcp) {
        my $where = _tcp_where($tcp);
        if ( $tcp->success ) {
            push @interpretations,
              "The destination accepted a TCP connection$where; the host and network path supported this connection at the time of the check.";
            push @next_steps, 'If the application still fails, investigate protocol, authentication, or application-level behavior.';
        }
        elsif ( $tcp->status eq 'connection_refused' ) {
            push @interpretations,
              "The destination actively refused the TCP connection$where. Possible explanations include no listener on that port, a service bound to another interface or port, or an actively rejecting firewall rule.";
            push @next_steps,
              'Check whether the intended service is listening on the requested address and port, then check firewall policy.';
        }
        elsif ( $tcp->status eq 'timeout' ) {
            push @interpretations,
              "No TCP response arrived before the timeout$where. Possible explanations include packet filtering, a routing problem, packet loss, an unreachable host, or a service that is not responding.";
            push @next_steps,
              'Compare the result from another network location and inspect routes, firewall policy, and service listener state.';
        }
        elsif ( $tcp->status eq 'host_unreachable' ) {
            push @interpretations,
              "The local networking stack reported the destination host as unreachable$where.";
            push @next_steps, 'Inspect local routes, the destination address, and any network or host firewall policy.';
        }
        elsif ( $tcp->status eq 'network_unreachable' ) {
            push @interpretations,
              "The local networking stack reported that no route to the destination network was available$where.";
            push @next_steps, 'Inspect the local routing table, interface state, gateway, and destination address.';
        }
        elsif ( $tcp->status eq 'permission_denied' ) {
            push @interpretations,
              "The operating system denied the TCP operation$where; this is a local permission or policy failure rather than evidence about the service.";
            push @next_steps, 'Check local privileges, endpoint-security policy, and firewall permissions.';
        }
        elsif ( $tcp->status eq 'dns_failure' ) {
            # DNS result may not have been run when this is used directly.
            push @interpretations,
              'The TCP check could not resolve its target name, so no connection attempt was made.';
            push @next_steps, 'Check the hostname and resolver configuration.';
        }
        elsif ( $tcp->status eq 'skipped' ) {
            push @interpretations, 'The TCP check was not run because a prerequisite check failed.';
        }
        elsif ( $tcp->status eq 'unsupported' ) {
            push @interpretations,
              'This TCP check was not available from the requested source in the current release.';
            push @next_steps, 'Run the check from local or wait for the explicitly authorized SSH execution phase.';
        }
        else {
            push @interpretations,
              "The TCP check failed with status '" . $tcp->status . "'; the available evidence does not distinguish the cause.";
            push @next_steps, 'Repeat the check with --verbose and inspect local network and service logs.';
        }
    }

    if ($ping) {
        if ( $ping->status eq 'timeout' ) {
            if ( $tcp && $tcp->success ) {
                push @interpretations,
                  'The reachability check timed out, but TCP succeeded; ICMP or the selected reachability probe may be filtered or unsupported. This does not prove that the host is down.';
                push @next_steps, 'Treat the successful TCP observation as stronger evidence for this service than the failed reachability probe.';
            }
            elsif ( !$tcp || !$tcp->success ) {
                push @interpretations,
                  'The reachability check timed out. The host or path may be unreachable, but filtering or an unsupported probe can produce the same observation.';
            }
        }
        elsif ( $ping->status eq 'dns_failure' ) {
            push @interpretations, 'The reachability check could not resolve the target name.'
              unless $dns && !$dns->success;
        }
        elsif ( $ping->status eq 'skipped' ) {
            push @interpretations, 'The reachability check was skipped because name resolution failed.';
        }
    }

    if ($trace) {
        if ( $trace->status eq 'timeout' ) {
            push @interpretations,
              'The route probe did not reach the destination before its limit; routers may suppress probes, so this alone does not identify the failing hop.';
            push @next_steps, 'Compare hop results from another source and verify routing and filtering at the first consistently missing hop.';
        }
        elsif ( !$trace->success ) {
            push @interpretations,
              'The route probe did not produce enough evidence to identify a failing hop.';
        }
    }

    my $summary = _summary( $dns, $ping, $tcp, $trace, $has_failure );

    # Keep suggestions unique while preserving the order in which the rules
    # produced them.
    my %seen;
    @next_steps = grep { defined $_ && !$seen{$_}++ } @next_steps;

    return {
        summary          => $summary,
        facts            => \@facts,
        interpretations  => \@interpretations,
        next_steps       => \@next_steps,
        has_failure      => $has_failure ? 1 : 0,
    };
}

sub _summary {
    my ( $dns, $ping, $tcp, $trace, $has_failure ) = @_;

    return 'Name resolution failed.' if $dns && !$dns->success;
    return 'The requested TCP service accepted a connection.' if $tcp && $tcp->success;
    return 'The destination refused the requested TCP connection.'
      if $tcp && $tcp->status eq 'connection_refused';
    return 'The requested TCP connection timed out.' if $tcp && $tcp->status eq 'timeout';
    return 'The route probe reached the destination.' if $trace && $trace->success;
    return 'The reachability check succeeded.' if $ping && $ping->success;
    return 'The diagnostic completed without a failure.' unless $has_failure;
    return 'The diagnostic found a failure, but the available evidence does not identify one cause.';
}

sub _tcp_where {
    my ($tcp) = @_;
    my $target = defined $tcp->target ? ' to ' . $tcp->target : '';
    my $port   = defined $tcp->port   ? ':' . $tcp->port : '';
    return "$target$port";
}

sub _fact_for {
    my ($result) = @_;
    my $check  = $result->check;
    my $target = defined $result->target ? $result->target : 'the target';

    if ( $check eq 'dns' ) {
        if ( $result->success ) {
            my $addresses = $result->detail->{addresses} || [];
            return "DNS resolved $target to " . join( ', ', @$addresses ) . '.';
        }
        return "DNS resolution for $target failed" . _with_error($result) . '.';
    }

    if ( $check eq 'ping' ) {
        return "The reachability check for $target succeeded" . _with_latency($result) . '.'
          if $result->success;
        return "The reachability check for $target returned " . $result->status
          . _with_error($result) . '.';
    }

    if ( $check eq 'tcp' ) {
        my $port = defined $result->port ? ':' . $result->port : '';
        return "TCP connection to $target$port succeeded" . _with_latency($result) . '.'
          if $result->success;
        return "TCP connection to $target$port returned " . $result->status
          . _with_error($result) . '.';
    }

    if ( $check eq 'trace' ) {
        my $hops = $result->detail->{hops} || [];
        return "Route probe to $target recorded " . scalar(@$hops) . ' hop(s) and reached the destination.'
          if $result->success;
        return "Route probe to $target returned " . $result->status
          . _with_error($result) . '.';
    }

    return "Check '$check' for $target returned " . $result->status . _with_error($result) . '.';
}

sub _with_latency {
    my ($result) = @_;
    return '' unless defined $result->latency_ms;
    return sprintf( ' in %.1f ms', $result->latency_ms );
}

sub _with_error {
    my ($result) = @_;
    return '' unless defined $result->error && length $result->error;
    return ': ' . $result->error;
}

1;

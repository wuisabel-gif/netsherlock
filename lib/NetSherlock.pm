package NetSherlock;

use strict;
use warnings;

our $VERSION = '0.1.0';

1;

__END__

=head1 NAME

NetSherlock - evidence-driven network diagnostics

=head1 DESCRIPTION

NetSherlock is a general-purpose network troubleshooting CLI.
It collects structured evidence (DNS, reachability, TCP connectivity,
routing), correlates it, and reports likely causes without overstating
what the evidence proves.

Internal pipeline:

    measurement -> evidence -> diagnosis -> presentation

Networking modules (DNS, Ping, Port, Trace) return NetSherlock::Result
objects. NetSherlock::Diagnose reasons over those results.
NetSherlock::Reporter formats them. No module performs work outside
its stage of the pipeline.

=cut

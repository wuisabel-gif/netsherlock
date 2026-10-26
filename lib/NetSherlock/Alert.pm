package NetSherlock::Alert;

use strict;
use warnings;

=head1 NAME

NetSherlock::Alert - turn flagged requests into webhook alerts

=head1 DESCRIPTION

Shapes a flagged L<NetSherlock::Result> into a chat-webhook message and
delivers it. Both Slack ("text") and Discord ("content") incoming-webhook
JSON shapes are supported; the shape is inferred from the webhook host and
can be forced.

A debounce keeps one noisy scan from firing hundreds of identical alerts:
alerts are collapsed per category+path within a time window. In dry-run
mode (the default for the CLI) nothing is sent - the payload that would be
posted is returned so the operator can see it first.

=cut

use JSON::PP ();

=head2 new(%opts)

    format   => 'slack' | 'discord' | 'auto'   (default 'auto')
    url      => webhook URL (used to infer the shape when format is 'auto')
    debounce => seconds to collapse repeat alerts for one category+path (default 60)
    dry_run  => truthy to format without posting

=cut

sub new {
    my ( $class, %opts ) = @_;
    my $self = {
        format   => $opts{format}   || 'auto',
        url      => $opts{url},
        debounce => defined $opts{debounce} ? $opts{debounce} : 60,
        dry_run  => $opts{dry_run} ? 1 : 0,
        _last    => {},    # "cat\0path" => epoch last sent
        sent     => 0,
        suppressed => 0,
    };
    return bless $self, $class;
}

# Resolve 'auto' to a concrete shape from the webhook host.
sub _shape {
    my ($self) = @_;
    return $self->{format} if $self->{format} && $self->{format} ne 'auto';
    my $url = $self->{url} || '';
    return 'discord' if $url =~ m{discord(?:app)?\.com}i;
    return 'slack';    # Slack-style {text:...} is the safe default
}

=head2 message_for($result)

Plain-text alert line for a flagged request.

=cut

sub message_for {
    my ( $self, $result ) = @_;
    my $d = $result->detail || {};
    my $reasons = ( $d->{reasons} && @{ $d->{reasons} } ) ? join( '; ', @{ $d->{reasons} } ) : $result->status;
    return sprintf(
        ':rotating_light: NetSherlock: likely attack (confidence %.2f) - %s %s - %s',
        ( $d->{confidence} || 0 ),
        ( $d->{method} || '?' ),
        ( $d->{path} // $result->target // '/' ),
        $reasons,
    );
}

=head2 payload_for($result)

The webhook JSON body (as a hashref) for the configured shape.

=cut

sub payload_for {
    my ( $self, $result ) = @_;
    my $text = $self->message_for($result);
    return $self->_shape eq 'discord' ? { content => $text } : { text => $text };
}

=head2 should_send($result, $now)

True unless an alert for this category+path was sent within the debounce
window. Records the send time when it returns true, so repeated calls in
the window are suppressed. $now defaults to time().

=cut

sub should_send {
    my ( $self, $result, $now ) = @_;
    $now = time() unless defined $now;
    my $d   = $result->detail || {};
    my $cat = ( $d->{categories} && @{ $d->{categories} } ) ? $d->{categories}[0] : 'attack';
    my $key = $cat . "\0" . ( $d->{path} // $result->target // '' );

    my $last = $self->{_last}{$key};
    if ( defined $last && $now - $last < $self->{debounce} ) {
        $self->{suppressed}++;
        return 0;
    }
    $self->{_last}{$key} = $now;
    return 1;
}

=head2 deliver($result, $now)

Debounce, then send (or, in dry-run, just format). Returns a hashref:

    { sent => 0|1, dry_run => 0|1, suppressed => 0|1, payload => {...}, error => $msg }

=cut

sub deliver {
    my ( $self, $result, $now ) = @_;
    return { sent => 0, suppressed => 1 } unless $self->should_send( $result, $now );

    my $payload = $self->payload_for($result);

    if ( $self->{dry_run} ) {
        return { sent => 0, dry_run => 1, payload => $payload };
    }

    my $error = $self->_post($payload);
    if ($error) {
        return { sent => 0, payload => $payload, error => $error };
    }
    $self->{sent}++;
    return { sent => 1, payload => $payload };
}

# Thin HTTP POST. HTTP::Tiny is core; HTTPS needs IO::Socket::SSL, which the
# error surfaces plainly if absent.
sub _post {
    my ( $self, $payload ) = @_;
    return 'no webhook URL configured' unless $self->{url};
    require HTTP::Tiny;
    my $json = JSON::PP->new->canonical->encode($payload);
    my $res  = HTTP::Tiny->new( timeout => 5, agent => 'NetSherlock/alert ' )->post(
        $self->{url},
        { headers => { 'Content-Type' => 'application/json' }, content => $json },
    );
    return undef if $res->{success};
    return sprintf( 'webhook POST failed: %s %s', $res->{status}, $res->{reason} // '' );
}

1;

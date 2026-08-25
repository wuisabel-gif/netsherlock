package NetSherlock::Config;

use strict;
use warnings;

use JSON::PP ();

=head1 NAME

NetSherlock::Config - load and validate generic diagnostic configurations

=head1 DESCRIPTION

This module supports JSON and the small, deliberately documented YAML
subset used by the example configuration. It avoids a mandatory non-core
YAML dependency while keeping configuration values data-only.

=cut

sub load_file {
    my ( $class, $path ) = @_;
    die 'configuration path is required' unless defined $path && length $path;

    open my $fh, '<', $path or die "cannot read configuration '$path': $!";
    local $/;
    my $text = <$fh>;
    close $fh or die "cannot close configuration '$path': $!";

    my $data;
    my $trimmed = $text;
    $trimmed =~ s/^\s+//;
    if ( $trimmed =~ /^[\[{]/ ) {
        $data = eval { JSON::PP::decode_json($text) };
        die "invalid JSON configuration: $@" if $@;
    }
    else {
        $data = _parse_yaml_subset($text);
    }

    my @errors = validate($data);
    die 'invalid configuration: ' . join( '; ', @errors ) if @errors;
    return $data;
}

sub validate {
    my ($data) = @_;
    my @errors;

    push @errors, 'top level must be a mapping'
      unless ref($data) eq 'HASH';
    return @errors unless ref($data) eq 'HASH';

    push @errors, 'hosts is required' unless exists $data->{hosts};
    push @errors, 'checks is required' unless exists $data->{checks};

    push @errors, 'hosts must be a mapping'
      if exists $data->{hosts} && ref( $data->{hosts} ) ne 'HASH';
    push @errors, 'checks must be a list'
      if exists $data->{checks} && ref( $data->{checks} ) ne 'ARRAY';

    if ( ref( $data->{hosts} ) eq 'HASH' ) {
        for my $name ( keys %{ $data->{hosts} } ) {
            my $host = $data->{hosts}{$name};
            push @errors, "host '$name' must be a mapping"
              unless ref($host) eq 'HASH';
            next unless ref($host) eq 'HASH';
            push @errors, "host '$name' requires address"
              unless defined $host->{address} && length $host->{address};
        }
    }

    if ( ref( $data->{checks} ) eq 'ARRAY' ) {
        for my $i ( 0 .. $#{ $data->{checks} } ) {
            my $check = $data->{checks}[$i];
            if ( ref($check) ne 'HASH' ) {
                push @errors, "checks[$i] must be a mapping";
                next;
            }
            for my $required (qw(from to protocol)) {
                push @errors, "checks[$i] requires $required"
                  unless defined $check->{$required} && length $check->{$required};
            }
            if ( defined $check->{to}
                && ref( $data->{hosts} ) eq 'HASH'
                && !exists $data->{hosts}{ $check->{to} } )
            {
                push @errors, "checks[$i] references unknown host '$check->{to}'";
            }
            if ( defined $check->{from}
                && $check->{from} ne 'local'
                && ref( $data->{hosts} ) eq 'HASH'
                && !exists $data->{hosts}{ $check->{from} } )
            {
                push @errors, "checks[$i] references unknown source '$check->{from}'";
            }
            if ( defined $check->{protocol} && $check->{protocol} ne 'tcp' ) {
                push @errors, "checks[$i] protocol '$check->{protocol}' is not supported (use tcp)";
            }
            if ( ( $check->{protocol} // '' ) eq 'tcp'
                && ( !defined $check->{port} || $check->{port} !~ /^\d+$/ || $check->{port} < 1 || $check->{port} > 65535 ) )
            {
                push @errors, "checks[$i] requires a TCP port from 1 to 65535";
            }
        }
    }

    return @errors;
}

sub _parse_yaml_subset {
    my ($text) = @_;
    my %data;
    my $section;
    my $current_host;
    my $current_check;
    my $line_number = 0;

    for my $raw ( split /\r?\n/, $text ) {
        ++$line_number;
        next if $raw =~ /^\s*$/ || $raw =~ /^\s*#/;

        # This subset has no multiline strings. Strip comments only when
        # separated by whitespace, preserving values such as host#name.
        $raw =~ s/\s+#.*$//;
        my ($indent) = $raw =~ /^(\s*)/;
        my $spaces = length($indent);
        my $line = $raw;
        $line =~ s/^\s+//;

        if ( $spaces == 0 && $line =~ /^([A-Za-z_][\w-]*):\s*$/ ) {
            $section = $1;
            die "invalid YAML line $line_number: unsupported section '$section'"
              unless $section eq 'hosts' || $section eq 'checks';
            $data{$section} = $section eq 'hosts' ? {} : [];
            $current_host  = undef;
            $current_check = undef;
            next;
        }

        if ( $section && $section eq 'hosts' ) {
            if ( $spaces == 2 && $line =~ /^([A-Za-z_][\w.-]*):\s*$/ ) {
                $current_host = $1;
                $data{hosts}{$current_host} = {};
                next;
            }
            if ( $spaces == 4 && $line =~ /^([A-Za-z_][\w-]*):\s*(.*?)\s*$/ && defined $current_host ) {
                $data{hosts}{$current_host}{$1} = _scalar($2);
                next;
            }
        }

        if ( $section && $section eq 'checks' ) {
            if ( $spaces == 2 && $line =~ /^-\s*(?:([A-Za-z_][\w-]*):\s*(.*))?$/ ) {
                $current_check = {};
                push @{ $data{checks} }, $current_check;
                $current_check->{$1} = _scalar($2) if defined $1;
                next;
            }
            if ( $spaces == 4 && $line =~ /^([A-Za-z_][\w-]*):\s*(.*?)\s*$/ && $current_check ) {
                $current_check->{$1} = _scalar($2);
                next;
            }
        }

        die "invalid YAML line $line_number";
    }

    return \%data;
}

sub _scalar {
    my ($value) = @_;
    $value //= '';
    $value =~ s/^['"](.*)['"]$/$1/;
    return 0 + $value if $value =~ /^\d+$/;
    return 1 if $value eq 'true';
    return 0 if $value eq 'false';
    return undef if $value eq 'null' || $value eq '~';
    return $value;
}

1;

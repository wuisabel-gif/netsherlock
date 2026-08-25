use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'NetSherlock',
    VERSION_FROM => 'lib/NetSherlock.pm',
    ABSTRACT     => 'Evidence-driven network diagnostics',
    AUTHOR       => 'NetSherlock contributors',
    LICENSE      => 'mit',
    EXE_FILES    => ['bin/netsherlock'],
    PREREQ_PM    => {
        'Getopt::Long' => 0,
        'IO::Socket::INET' => 0,
        'JSON::PP' => 0,
        'Net::Ping' => 0,
        'Socket' => 0,
        'Test::More' => 0,
        'Time::HiRes' => 0,
    },
    MIN_PERL_VERSION => '5.16.0',
);

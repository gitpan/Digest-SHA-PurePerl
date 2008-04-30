require 5.003000;

use ExtUtils::MakeMaker;

my $PM = 'lib/Digest/SHA/PurePerl.pm';

%att = (
	'NAME'		=> 'Digest::SHA::PurePerl',
	'VERSION_FROM'	=> $PM,
	'EXE_FILES'	=> [ 'shasum' ],
);

my $MMversion = $ExtUtils::MakeMaker::VERSION || 0;
$att{NO_META} = 1 unless $MMversion < 6.10_03;

WriteMakefile(%att);

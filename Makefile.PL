require 5.003000;

use ExtUtils::MakeMaker;

%att = (
	'NAME'		=> 'Digest::SHA::PurePerl',
	'VERSION_FROM'	=> 'PurePerl.pm',
	'EXE_FILES'	=> [ 'shasum' ],
);

my $MMversion = $ExtUtils::MakeMaker::VERSION || 0;
$att{NO_META} = 1 unless $MMversion < 6.10_03;

WriteMakefile(%att);

require 5.003000;

use ExtUtils::MakeMaker;

%att = (
	'NAME'		=> 'Digest::SHA::PurePerl',
	'VERSION_FROM'	=> 'PurePerl.pm',
	'EXE_FILES'	=> [ 'shasum' ],
);

$att{NO_META} = 1
	unless $ExtUtils::MakeMaker::VERSION < 6.10_03;

WriteMakefile(%att);

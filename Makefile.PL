require 5.006000;

use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'		=> 'Digest::SHA::PurePerl',
	'VERSION_FROM'	=> 'PurePerl.pm',
	'PREREQ_PM'	=> {},
	'AUTHOR'	=> 'Mark Shelor <mshelor@cpan.org>',
	'NO_META'	=> 1,
	'EXE_FILES'	=> [ 'shasum' ]
);

use Test;
use strict;
use integer;
use File::Spec;
use File::Basename qw(dirname);

my(@vec, @alg, @rsp, $numtests);

BEGIN { 
	@vec = (
"abc",
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
"abc",
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
"abc",
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
"abc"
	);

	@alg = (1, 1, 224, 224, 256, 256, 1);

	@rsp = (
"a9993e364706816aba3e25717850c26c9cd0d89d",
"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
"75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
"a9993e364706816aba3e25717850c26c9cd0d89b"	# incorrect!
	);

	$numtests = scalar(@vec);
	plan tests => $numtests;
}


	# paths for shasum script and blib directory

my $SHASUM = File::Spec->canonpath(dirname($0) . "/../blib/script/shasum");
my $LIBDIR = File::Spec->canonpath(dirname($0) . "/..");


	# create a separate data file for each vec

for (my $i = 0; $i < @vec; $i++) {
	open(F, ">tmp.$i"); binmode(F); print F $vec[$i]; close(F);
}


	# create an associated check file

open(F, ">tmp.chk");
for (my $i = 0; $i < @rsp; $i++) {
	print F $rsp[$i], " *tmp.$i\n";
}
close(F);


	# use shasum to validate the check file:
	#	all entries are correct except the last one;
	#	make sure shasum catches it, and approves the others

my @out = `$^X -Mblib=$LIBDIR $SHASUM -c tmp.chk`;

my $skip = scalar(@out) != $numtests;
@out = (1 .. $numtests) if $skip;

for (@out) { s/\s+$// }
skip($skip, pop(@out) =~ /FAILED$/);
for (@out) { skip($skip, /OK$/) }


	# remove temporary files

unlink("tmp.chk");
for (my $i = 0; $i < @vec; $i++) { unlink("tmp.$i") }
use Test;
use strict;
use integer;

BEGIN { plan tests => 1 }

my $vec = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
my $rsp = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

my $DAT = "shasum.dat";
my $OUT = "shasum.out";

open(F, ">$DAT"); binmode(F); print F $vec; close(F);

my @SARG = @ARGV; open(SOUT, ">&STDOUT");

@ARGV = ("-a", "256", $DAT);
open(STDOUT, ">$OUT"); do "./blib/script/shasum"; close(STDOUT);

@ARGV = @SARG; open(STDOUT, ">&SOUT"); close(SOUT);

open(F, "<$OUT"); my $line = <F>; close(F);
my ($sum) = ($line =~ /^(\S+)\s+/);
unlink($DAT, $OUT);

ok($sum, $rsp);

use Test;
use strict;
use integer;
use Digest::SHA::PurePerl qw(sha384_hex);

BEGIN { plan tests => 2 }

my @vecs = (
	"abc",
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
);

my @sha384rsp = (
	"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
);

my $skip = sha384_hex("") ? 0 : 1;

for (my $i = 0; $i < @vecs; $i++) {
	skip($skip, sha384_hex($vecs[$i]), $sha384rsp[$i]);
}

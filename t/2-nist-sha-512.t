use Test;
use strict;
use integer;
use Digest::SHA::PurePerl qw(sha512_hex);

BEGIN { plan tests => 2 }

my @vecs = (
	"abc",
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
);

my @sha512rsp = (
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
);

my $skip = sha512_hex("") ? 0 : 1;

for (my $i = 0; $i < @vecs; $i++) {
	skip($skip, sha512_hex($vecs[$i]), $sha512rsp[$i]);
}

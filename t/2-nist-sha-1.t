use Test;
use strict;
use integer;
use Digest::SHA::PurePerl qw(sha1_hex);

# BEGIN { plan tests => 3 }
BEGIN { plan tests => 2 }

my @vecs = (
	"abc",
	"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
#	"a" x 1000000
);

my @sha1rsp = (
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"84983e441c3bd26ebaae4aa1f95129e5e54670f1",
	"34aa973cd4c4daa4f61eeb2bdbad27316534016f"
);

for (my $i = 0; $i < @vecs; $i++) {
	ok(sha1_hex($vecs[$i]), $sha1rsp[$i]);
}

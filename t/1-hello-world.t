use Test;
use Digest::SHA::PurePerl qw(sha1);
use strict;
use integer;

BEGIN { plan tests => 1 }

my @vecs = (
	"hello world"
);

my @rsp = (
	pack("H*", "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
);

for (my $i = 0; $i < @vecs; $i++) {
	ok(sha1($vecs[$i]), $rsp[$i]);
}

use Test;
use strict;
use integer;
use Digest::SHA::PurePerl qw(sha1_base64 sha224_base64 sha256_base64);

BEGIN { plan tests => 3 }

# Base64 digests of "abc" for SHA-1/224/256/384/512

my $data = "abc";
my @vecs = (
	\&sha1_base64, "qZk+NkcGgWq6PiVxeFDCbJzQ2J0",
	\&sha224_base64, "Iwl9IjQF2CKGQqR3vaJVsyqtvOS9oLP342ydpw",
	\&sha256_base64, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
);

my $fcn;
my $rsp;
my $skip;

while (@vecs) {
	$fcn = shift(@vecs);
	$rsp = shift(@vecs);
	$skip = &$fcn("") ? 0 : 1;
	skip($skip, &$fcn($data), $rsp);
}

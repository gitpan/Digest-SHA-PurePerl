use Test;
use strict;
use integer;
use Digest::SHA::PurePerl;

BEGIN { plan tests => 1 }

my $i;
my $bitstr = pack("B*", "1" x 399);
my $state = Digest::SHA::PurePerl->new("sHa1");

# Note that (1 + 2 + ... + 399) + 200 = 80000

for ($i = 0; $i <= 399; $i++) {
	$state->add_bits($bitstr, $i);
}
$state->add_bits($bitstr, 200);

ok(
	$state->hexdigest,
	"11003389959355c2773af6b0f36d842fe430ec49"
);

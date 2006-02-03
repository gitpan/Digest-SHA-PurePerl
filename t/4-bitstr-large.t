use Test;
use strict;
use integer;
use Digest::SHA::PurePerl;

BEGIN {
	if ($ENV{PERL_CORE}) {
		chdir 't' if -d 't';
		@INC = '../lib';
	}
}

BEGIN { plan tests => 1 }

my $i;
my $bitstr = pack("B*", "11111111" x 100);
my $state = Digest::SHA::PurePerl->new("1");

$state->add_bits($bitstr, 1);	# creates an alignment nuisance
for ($i = 0; $i < 99; $i++) {
	$state->add_bits($bitstr, 800);
}
$state->add_bits($bitstr, 799);

ok(
	$state->hexdigest,
	"11003389959355c2773af6b0f36d842fe430ec49"
);

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

my $reps = 80000;
my $bitstr = pack("B*", "11111111" x 127);
my $maxbits = 8 * 127;
my $state = Digest::SHA::PurePerl->new(1);
my $num;

while ($reps > $maxbits) {
	$num = int(rand($maxbits));
	$state->add_bits($bitstr, $num);
	$reps -= $num;
}
$state->add_bits($bitstr, $reps);

ok(
	$state->hexdigest,
	"11003389959355c2773af6b0f36d842fe430ec49"
);

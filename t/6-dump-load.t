use Test;
use strict;
use integer;
use Digest::SHA::PurePerl;
use File::Basename qw(dirname);
use File::Spec;

BEGIN { plan tests => 2 }

my @sharsp = (
	"34aa973cd4c4daa4f61eeb2bdbad27316534016f",
	"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
);

my @ext = (1, 256);
my $data = "a" x 999998;
my $skip;

for (my $i = 0; $i < 2; $i++) {
	my $digest;
	my $state;
	my $file;
	my $filename;
	$filename = dirname($0) . "/state/state.$ext[$i]";
	$file = File::Spec->canonpath($filename);
	unless ($state = Digest::SHA::PurePerl->load($file)) {
		$state = Digest::SHA::PurePerl->new($ext[$i]);
		$state->add($data);
		$state->dump($file);
		$state->load($file);
	}
	$state->add_bits($data, 16);
	$digest = $state->hexdigest;
	ok($digest, $sharsp[$i]);
}

package Digest::SHA::PurePerl;

use strict;
use warnings;
use integer;

our $VERSION = '0.03';

require Exporter;
our @ISA = qw(Exporter);

our @EXPORT_OK = qw(
	hmac_sha1	hmac_sha1_base64	hmac_sha1_hex
	hmac_sha224	hmac_sha224_base64	hmac_sha224_hex
	hmac_sha256	hmac_sha256_base64	hmac_sha256_hex
	sha1		sha1_base64		sha1_hex
	sha224		sha224_base64		sha224_hex
	sha256		sha256_base64		sha256_hex);

# If possible, inherit from Digest::base (which depends on MIME::Base64)

eval {
	require MIME::Base64;
	require Digest::base;
	push(@ISA, 'Digest::base');
};
if ($@) {
	*addfile = \&_addfile;
	*hexdigest = \&_hexdigest;
	*b64digest = \&_b64digest;
}

# Preloaded methods go here.

# ref. src/sha.c from Digest::SHA

my $MAX32 = 0xffffffff;
my $TWO32 = 4294967296;

my($K1, $K2, $K3, $K4) = (	# SHA-1 constants
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
);

my @K256 = (			# SHA-224/256 constants
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
);

my @H01 = (			# SHA-1 initial hash value
	0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
	0xc3d2e1f0
);

my @H0224 = (			# SHA-224 initial hash value
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
);

my @H0256 = (			# SHA-256 initial hash value
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
);

# Routines with a "_c_" prefix create Perl code-fragments that are
# eval-ed at initialization.  This technique emulates the behavior
# of the C preprocessor, thereby allowing the optimized transform
# code from Digest::SHA to be more easily rendered in Perl.
#
# BTW, all these gyrations with cryptic runtime code generation
# result in a 20% performance increase compared to the initial
# version, which was MUCH easier to understand.  Normally, such a
# trade-off wouldn't be worth it.  But given the workhorse nature
# of digest computation routines, an exception was made here.

sub _c_SL32 {			# code to shift $x left by $n bits
	my($x, $n) = @_;
	"($x << $n)";		# even works for 64-bit integers
				# since the upper 32 bits are
				# eventually discarded in _digcpy
}

sub _c_SR32 {			# code to shift $x right by $n bits
	my($x, $n) = @_;
	my $mask = (1 << (32 - $n)) - 1;
	"(($x >> $n) & $mask)";		# Perl does arithmetic shift, so	
					# explicitly clear upper bits
}

sub _c_Ch { my($x, $y, $z) = @_; "($z ^ ($x & ($y ^ $z)))" }
sub _c_Pa { my($x, $y, $z) = @_; "($x ^ $y ^ $z)" }
sub _c_Ma { my($x, $y, $z) = @_; "(($x & $y) | ($z & ($x | $y)))" }

sub _c_ROTR {			# code to rotate $x right by $n bits
	my($x, $n) = @_;
	"(" . _c_SR32($x, $n) . " | " . _c_SL32($x, 32 - $n) . ")";
}

sub _c_ROTL {			# code to rotate $x left by $n bits
	my($x, $n) = @_;
	"(" . _c_SL32($x, $n) . " | " . _c_SR32($x, 32 - $n) . ")";
}

sub _c_SIGMA0 {			# ref. NIST SHA standard
	my($x) = @_;
	"(" . _c_ROTR($x,  2) . " ^ " . _c_ROTR($x, 13) . " ^ " .
		_c_ROTR($x, 22) . ")";
}

sub _c_SIGMA1 {
	my($x) = @_;
	"(" . _c_ROTR($x,  6) . " ^ " . _c_ROTR($x, 11) . " ^ " .
		_c_ROTR($x, 25) . ")";
}

sub _c_sigma0 {
	my($x) = @_;
	"(" . _c_ROTR($x,  7) . " ^ " . _c_ROTR($x, 18) . " ^ " .
		_c_SR32($x,  3) . ")";
}

sub _c_sigma1 {
	my($x) = @_;
	"(" . _c_ROTR($x, 17) . " ^ " . _c_ROTR($x, 19) . " ^ " .
		_c_SR32($x, 10) . ")";
}

sub _c_M1Ch {			# ref. Digest::SHA sha.c (sha1 routine)
	my($a, $b, $c, $d, $e, $k, $w) = @_;
	"$e += " . _c_ROTL($a, 5) . " + " . _c_Ch($b, $c, $d) .
		" + $k + $w; $b = " . _c_ROTL($b, 30) . ";\n";
}

sub _c_M1Pa {
	my($a, $b, $c, $d, $e, $k, $w) = @_;
	"$e += " . _c_ROTL($a, 5) . " + " . _c_Pa($b, $c, $d) .
		" + $k + $w; $b = " . _c_ROTL($b, 30) . ";\n";
}

sub _c_M1Ma {
	my($a, $b, $c, $d, $e, $k, $w) = @_;
	"$e += " . _c_ROTL($a, 5) . " + " . _c_Ma($b, $c, $d) .
		" + $k + $w; $b = " . _c_ROTL($b, 30) . ";\n";
}

sub _c_M11Ch { my($k, $w) = @_; _c_M1Ch('$a', '$b', '$c', '$d', '$e', $k, $w) }
sub _c_M11Pa { my($k, $w) = @_; _c_M1Pa('$a', '$b', '$c', '$d', '$e', $k, $w) }
sub _c_M11Ma { my($k, $w) = @_; _c_M1Ma('$a', '$b', '$c', '$d', '$e', $k, $w) }
sub _c_M12Ch { my($k, $w) = @_; _c_M1Ch('$e', '$a', '$b', '$c', '$d', $k, $w) }
sub _c_M12Pa { my($k, $w) = @_; _c_M1Pa('$e', '$a', '$b', '$c', '$d', $k, $w) }
sub _c_M12Ma { my($k, $w) = @_; _c_M1Ma('$e', '$a', '$b', '$c', '$d', $k, $w) }
sub _c_M13Ch { my($k, $w) = @_; _c_M1Ch('$d', '$e', '$a', '$b', '$c', $k, $w) }
sub _c_M13Pa { my($k, $w) = @_; _c_M1Pa('$d', '$e', '$a', '$b', '$c', $k, $w) }
sub _c_M13Ma { my($k, $w) = @_; _c_M1Ma('$d', '$e', '$a', '$b', '$c', $k, $w) }
sub _c_M14Ch { my($k, $w) = @_; _c_M1Ch('$c', '$d', '$e', '$a', '$b', $k, $w) }
sub _c_M14Pa { my($k, $w) = @_; _c_M1Pa('$c', '$d', '$e', '$a', '$b', $k, $w) }
sub _c_M14Ma { my($k, $w) = @_; _c_M1Ma('$c', '$d', '$e', '$a', '$b', $k, $w) }
sub _c_M15Ch { my($k, $w) = @_; _c_M1Ch('$b', '$c', '$d', '$e', '$a', $k, $w) }
sub _c_M15Pa { my($k, $w) = @_; _c_M1Pa('$b', '$c', '$d', '$e', '$a', $k, $w) }
sub _c_M15Ma { my($k, $w) = @_; _c_M1Ma('$b', '$c', '$d', '$e', '$a', $k, $w) }

sub _c_W11 { my($s) = @_; '$W[' . (($s +  0) & 0xf) . ']' }
sub _c_W12 { my($s) = @_; '$W[' . (($s + 13) & 0xf) . ']' }
sub _c_W13 { my($s) = @_; '$W[' . (($s +  8) & 0xf) . ']' }
sub _c_W14 { my($s) = @_; '$W[' . (($s +  2) & 0xf) . ']' }

sub _c_A1 {
	my($s) = @_;
	my $tmp = _c_W11($s) . " ^ " . _c_W12($s) . " ^ " .
		_c_W13($s) . " ^ " . _c_W14($s);
	"((\$tmp = $tmp), (" . _c_W11($s) . " = " . _c_ROTL('$tmp', 1) . "))";
}

# The following code emulates the "sha1" routine from Digest::SHA sha.c

my $sha1_code =
'sub _sha1 {
	my($self, $block) = @_;
	my(@W, $a, $b, $c, $d, $e, $tmp);

	@W = unpack("N16", $block);
	($a, $b, $c, $d, $e) = @{$self->{H}};
' .
	_c_M11Ch('$K1', '$W[ 0]'  ) . _c_M12Ch('$K1', '$W[ 1]'  ) .
	_c_M13Ch('$K1', '$W[ 2]'  ) . _c_M14Ch('$K1', '$W[ 3]'  ) .
	_c_M15Ch('$K1', '$W[ 4]'  ) . _c_M11Ch('$K1', '$W[ 5]'  ) .
	_c_M12Ch('$K1', '$W[ 6]'  ) . _c_M13Ch('$K1', '$W[ 7]'  ) .
	_c_M14Ch('$K1', '$W[ 8]'  ) . _c_M15Ch('$K1', '$W[ 9]'  ) .
	_c_M11Ch('$K1', '$W[10]'  ) . _c_M12Ch('$K1', '$W[11]'  ) .
	_c_M13Ch('$K1', '$W[12]'  ) . _c_M14Ch('$K1', '$W[13]'  ) .
	_c_M15Ch('$K1', '$W[14]'  ) . _c_M11Ch('$K1', '$W[15]'  ) .
	_c_M12Ch('$K1', _c_A1( 0) ) . _c_M13Ch('$K1', _c_A1( 1) ) .
	_c_M14Ch('$K1', _c_A1( 2) ) . _c_M15Ch('$K1', _c_A1( 3) ) .
	_c_M11Pa('$K2', _c_A1( 4) ) . _c_M12Pa('$K2', _c_A1( 5) ) .
	_c_M13Pa('$K2', _c_A1( 6) ) . _c_M14Pa('$K2', _c_A1( 7) ) .
	_c_M15Pa('$K2', _c_A1( 8) ) . _c_M11Pa('$K2', _c_A1( 9) ) .
	_c_M12Pa('$K2', _c_A1(10) ) . _c_M13Pa('$K2', _c_A1(11) ) .
	_c_M14Pa('$K2', _c_A1(12) ) . _c_M15Pa('$K2', _c_A1(13) ) .
	_c_M11Pa('$K2', _c_A1(14) ) . _c_M12Pa('$K2', _c_A1(15) ) .
	_c_M13Pa('$K2', _c_A1( 0) ) . _c_M14Pa('$K2', _c_A1( 1) ) .
	_c_M15Pa('$K2', _c_A1( 2) ) . _c_M11Pa('$K2', _c_A1( 3) ) .
	_c_M12Pa('$K2', _c_A1( 4) ) . _c_M13Pa('$K2', _c_A1( 5) ) .
	_c_M14Pa('$K2', _c_A1( 6) ) . _c_M15Pa('$K2', _c_A1( 7) ) .
	_c_M11Ma('$K3', _c_A1( 8) ) . _c_M12Ma('$K3', _c_A1( 9) ) .
	_c_M13Ma('$K3', _c_A1(10) ) . _c_M14Ma('$K3', _c_A1(11) ) .
	_c_M15Ma('$K3', _c_A1(12) ) . _c_M11Ma('$K3', _c_A1(13) ) .
	_c_M12Ma('$K3', _c_A1(14) ) . _c_M13Ma('$K3', _c_A1(15) ) .
	_c_M14Ma('$K3', _c_A1( 0) ) . _c_M15Ma('$K3', _c_A1( 1) ) .
	_c_M11Ma('$K3', _c_A1( 2) ) . _c_M12Ma('$K3', _c_A1( 3) ) .
	_c_M13Ma('$K3', _c_A1( 4) ) . _c_M14Ma('$K3', _c_A1( 5) ) .
	_c_M15Ma('$K3', _c_A1( 6) ) . _c_M11Ma('$K3', _c_A1( 7) ) .
	_c_M12Ma('$K3', _c_A1( 8) ) . _c_M13Ma('$K3', _c_A1( 9) ) .
	_c_M14Ma('$K3', _c_A1(10) ) . _c_M15Ma('$K3', _c_A1(11) ) .
	_c_M11Pa('$K4', _c_A1(12) ) . _c_M12Pa('$K4', _c_A1(13) ) .
	_c_M13Pa('$K4', _c_A1(14) ) . _c_M14Pa('$K4', _c_A1(15) ) .
	_c_M15Pa('$K4', _c_A1( 0) ) . _c_M11Pa('$K4', _c_A1( 1) ) .
	_c_M12Pa('$K4', _c_A1( 2) ) . _c_M13Pa('$K4', _c_A1( 3) ) .
	_c_M14Pa('$K4', _c_A1( 4) ) . _c_M15Pa('$K4', _c_A1( 5) ) .
	_c_M11Pa('$K4', _c_A1( 6) ) . _c_M12Pa('$K4', _c_A1( 7) ) .
	_c_M13Pa('$K4', _c_A1( 8) ) . _c_M14Pa('$K4', _c_A1( 9) ) .
	_c_M15Pa('$K4', _c_A1(10) ) . _c_M11Pa('$K4', _c_A1(11) ) .
	_c_M12Pa('$K4', _c_A1(12) ) . _c_M13Pa('$K4', _c_A1(13) ) .
	_c_M14Pa('$K4', _c_A1(14) ) . _c_M15Pa('$K4', _c_A1(15) ) .

'	$self->{H}->[0] += $a; $self->{H}->[1] += $b; $self->{H}->[2] += $c;
	$self->{H}->[3] += $d; $self->{H}->[4] += $e;
}
';

eval($sha1_code);

sub _c_M2 {			# ref. Digest::SHA sha.c (sha256 routine)
	my($a, $b, $c, $d, $e, $f, $g, $h, $w) = @_;
	"\$T1 = $h + " . _c_SIGMA1($e) . " + " . _c_Ch($e, $f, $g) .
		" + \$K256[\$i++] + $w; $h = \$T1 + " . _c_SIGMA0($a) .
		" + " . _c_Ma($a, $b, $c) . "; $d += \$T1;\n";
}

sub _c_M21 { _c_M2('$a', '$b', '$c', '$d', '$e', '$f', '$g', '$h', $_[0]) }
sub _c_M22 { _c_M2('$h', '$a', '$b', '$c', '$d', '$e', '$f', '$g', $_[0]) }
sub _c_M23 { _c_M2('$g', '$h', '$a', '$b', '$c', '$d', '$e', '$f', $_[0]) }
sub _c_M24 { _c_M2('$f', '$g', '$h', '$a', '$b', '$c', '$d', '$e', $_[0]) }
sub _c_M25 { _c_M2('$e', '$f', '$g', '$h', '$a', '$b', '$c', '$d', $_[0]) }
sub _c_M26 { _c_M2('$d', '$e', '$f', '$g', '$h', '$a', '$b', '$c', $_[0]) }
sub _c_M27 { _c_M2('$c', '$d', '$e', '$f', '$g', '$h', '$a', '$b', $_[0]) }
sub _c_M28 { _c_M2('$b', '$c', '$d', '$e', '$f', '$g', '$h', '$a', $_[0]) }

sub _c_W21 { my($s) = @_; '$W[' . (($s +  0) & 0xf) . ']' }
sub _c_W22 { my($s) = @_; '$W[' . (($s + 14) & 0xf) . ']' }
sub _c_W23 { my($s) = @_; '$W[' . (($s +  9) & 0xf) . ']' }
sub _c_W24 { my($s) = @_; '$W[' . (($s +  1) & 0xf) . ']' }

sub _c_A2 {
	my($s) = @_;
	"(" . _c_W21($s) . " += " . _c_sigma1(_c_W22($s)) . " + " .
		_c_W23($s) . " + " . _c_sigma0(_c_W24($s)) . ")";
}

# The following code emulates the "sha256" routine from Digest::SHA sha.c

my $sha256_code =
'sub _sha256 {
	my($self, $block) = @_;
	my(@W, $a, $b, $c, $d, $e, $f, $g, $h, $i, $T1);

	@W = unpack("N16", $block);
	($a, $b, $c, $d, $e, $f, $g, $h) = @{$self->{H}};
' .
	_c_M21('$W[ 0]' ) . _c_M22('$W[ 1]' ) . _c_M23('$W[ 2]' ) .
	_c_M24('$W[ 3]' ) . _c_M25('$W[ 4]' ) . _c_M26('$W[ 5]' ) .
	_c_M27('$W[ 6]' ) . _c_M28('$W[ 7]' ) . _c_M21('$W[ 8]' ) .
	_c_M22('$W[ 9]' ) . _c_M23('$W[10]' ) . _c_M24('$W[11]' ) .
	_c_M25('$W[12]' ) . _c_M26('$W[13]' ) . _c_M27('$W[14]' ) .
	_c_M28('$W[15]' ) .
	_c_M21(_c_A2( 0)) . _c_M22(_c_A2( 1)) . _c_M23(_c_A2( 2)) .
	_c_M24(_c_A2( 3)) . _c_M25(_c_A2( 4)) . _c_M26(_c_A2( 5)) .
	_c_M27(_c_A2( 6)) . _c_M28(_c_A2( 7)) . _c_M21(_c_A2( 8)) .
	_c_M22(_c_A2( 9)) . _c_M23(_c_A2(10)) . _c_M24(_c_A2(11)) .
	_c_M25(_c_A2(12)) . _c_M26(_c_A2(13)) . _c_M27(_c_A2(14)) .
	_c_M28(_c_A2(15)) . _c_M21(_c_A2( 0)) . _c_M22(_c_A2( 1)) .
	_c_M23(_c_A2( 2)) . _c_M24(_c_A2( 3)) . _c_M25(_c_A2( 4)) .
	_c_M26(_c_A2( 5)) . _c_M27(_c_A2( 6)) . _c_M28(_c_A2( 7)) .
	_c_M21(_c_A2( 8)) . _c_M22(_c_A2( 9)) . _c_M23(_c_A2(10)) .
	_c_M24(_c_A2(11)) . _c_M25(_c_A2(12)) . _c_M26(_c_A2(13)) .
	_c_M27(_c_A2(14)) . _c_M28(_c_A2(15)) . _c_M21(_c_A2( 0)) .
	_c_M22(_c_A2( 1)) . _c_M23(_c_A2( 2)) . _c_M24(_c_A2( 3)) .
	_c_M25(_c_A2( 4)) . _c_M26(_c_A2( 5)) . _c_M27(_c_A2( 6)) .
	_c_M28(_c_A2( 7)) . _c_M21(_c_A2( 8)) . _c_M22(_c_A2( 9)) .
	_c_M23(_c_A2(10)) . _c_M24(_c_A2(11)) . _c_M25(_c_A2(12)) .
	_c_M26(_c_A2(13)) . _c_M27(_c_A2(14)) . _c_M28(_c_A2(15)) .

'	$self->{H}->[0] += $a; $self->{H}->[1] += $b; $self->{H}->[2] += $c;
	$self->{H}->[3] += $d; $self->{H}->[4] += $e; $self->{H}->[5] += $f;
	$self->{H}->[6] += $g; $self->{H}->[7] += $h;
}
';

eval($sha256_code);

sub _SETBIT {
	my($bitstr, $pos) = @_;
	my @c = unpack("C*", $bitstr);
	$c[$pos >> 3] = 0x00 unless defined $c[$pos >> 3];
	$c[$pos >> 3] |= (0x01 << (7 - $pos % 8));
	pack("C*", @c);
}

sub _CLRBIT {
	my($bitstr, $pos) = @_;
	my @c = unpack("C*", $bitstr);
	$c[$pos >> 3] = 0x00 unless defined $c[$pos >> 3];
	$c[$pos >> 3] &= ~(0x01 << (7 - $pos % 8));
	pack("C*", @c);
}

sub _BYTECNT {
	my($bitcnt) = @_;
	$bitcnt > 0 ? 1 + (($bitcnt - 1) >> 3) : 0;
}

sub _digcpy {
	my($self) = @_;
	my $fmt = "N" . ($self->{digestlen} >> 2);
	for (@{$self->{H}}) { $_ &= $MAX32 }
	$self->{digest} = pack($fmt, @{$self->{H}});
}

sub _sharewind {
	my($self) = @_;
	$self->{block} = ""; $self->{blockcnt} = 0;
	no integer; $self->{len} = 0; use integer;
	if ($self->{alg} == 1) {
		$self->{sha} = \&_sha1;
		$self->{H} = [@H01];
		$self->{blocksize} = 512;
		$self->{digestlen} = 20;
	}
	elsif ($self->{alg} == 224) {
		$self->{sha} = \&_sha256;
		$self->{H} = [@H0224];
		$self->{blocksize} = 512;
		$self->{digestlen} = 28;
	}
	elsif ($self->{alg} == 256) {
		$self->{sha} = \&_sha256;
		$self->{H} = [@H0256];
		$self->{blocksize} = 512;
		$self->{digestlen} = 32;
	}
	else { return }
	push(@{$self->{H}}, 0) while scalar(@{$self->{H}}) < 8;
	$self;
}

sub _shaopen {
	my($alg) = @_;
	my($self);
	$self->{alg} = $alg;
	_sharewind($self);
}

sub _shadirect {
	my($bitstr, $bitcnt, $self) = @_;
	my $savecnt = $bitcnt;
	my $offset = 0;
	while ($bitcnt >= $self->{blocksize}) {
		$self->{sha}->($self, substr($bitstr, $offset, 64));
		$offset += 64;
		$bitcnt -= $self->{blocksize};
	}
	if ($bitcnt > 0) {
		$self->{block} = substr($bitstr, $offset, _BYTECNT($bitcnt));
		$self->{blockcnt} = $bitcnt;
	}
	$savecnt;
}

sub _shabytes {
	my($bitstr, $bitcnt, $self) = @_;
	my($numbits);
	my $savecnt = $bitcnt;
	if ($self->{blockcnt} + $bitcnt >= $self->{blocksize}) {
		$numbits = $self->{blocksize} - $self->{blockcnt};
		$self->{block} .= substr($bitstr, 0, $numbits >> 3);
		$bitcnt -= $numbits;
		$bitstr = substr($bitstr, $numbits >> 3, _BYTECNT($bitcnt));
		$self->{sha}->($self, $self->{block});
		$self->{block} = "";
		$self->{blockcnt} = 0;
		_shadirect($bitstr, $bitcnt, $self);
	}
	else {
		$self->{block} .= substr($bitstr, 0, _BYTECNT($bitcnt));
		$self->{blockcnt} += $bitcnt;
	}
	$savecnt;
}

sub _shabits {
	my($bitstr, $bitcnt, $self) = @_;
	my(@buf);
	my $numbytes = _BYTECNT($bitcnt);
	my $savecnt = $bitcnt;
	my $gap = 8 - $self->{blockcnt} % 8;
	my @c = unpack("C*", $self->{block});
	my @b = unpack("C" . $numbytes, $bitstr);
	$c[$self->{blockcnt}>>3] &= (~0 << $gap);
	$c[$self->{blockcnt}>>3] |= $b[0] >> (8 - $gap);
	$self->{block} = pack("C*", @c);
	$self->{blockcnt} += ($bitcnt < $gap) ? $bitcnt : $gap;
	return($savecnt) if $bitcnt < $gap;
	if ($self->{blockcnt} == $self->{blocksize}) {
		$self->{sha}->($self, $self->{block});
		$self->{block} = "";
		$self->{blockcnt} = 0;
	}
	return($savecnt) if ($bitcnt -= $gap) == 0;
	for (my $i = 0; $i < $numbytes - 1; $i++) {
		$buf[$i] = (($b[$i] << $gap) & 0xff) | ($b[$i+1] >> (8 - $gap));
	}
	$buf[$numbytes-1] = ($b[$numbytes-1] << $gap) & 0xff;
	_shabytes(pack("C*", @buf), $bitcnt, $self);
	$savecnt;
}

sub _shawrite {
	my($bitstr, $bitcnt, $self) = @_;
	return(0) if ($bitcnt == 0);
	no integer; $self->{len} += $bitcnt; use integer;
	if ($self->{blockcnt} == 0) {
		return(_shadirect($bitstr, $bitcnt, $self));
	}
	elsif ($self->{blockcnt} % 8 == 0) {
		return(_shabytes($bitstr, $bitcnt, $self));
	}
	else {
		return(_shabits($bitstr, $bitcnt, $self));
	}
}

sub _shafinish {
	my($self) = @_;
	my $LENPOS = 448;
	$self->{block} = _SETBIT($self->{block}, $self->{blockcnt}++);
	while ($self->{blockcnt} > $LENPOS) {
		if ($self->{blockcnt} == $self->{blocksize}) {
			$self->{sha}->($self, $self->{block});
			$self->{block} = "";
			$self->{blockcnt} = 0;
		}
		else {
			$self->{block} =
				_CLRBIT($self->{block}, $self->{blockcnt}++);
		}
	}
	while ($self->{blockcnt} < $LENPOS) {
		$self->{block} = _CLRBIT($self->{block}, $self->{blockcnt}++);
	}
	no integer;
		$self->{block} .= pack("N", int($self->{len} / $TWO32));
		$self->{block} .= pack("N", $self->{len} % $TWO32);
	use integer;
	$self->{sha}->($self, $self->{block});
	$self->{blockcnt} = 0;
	_digcpy($self);
}

sub _shadigest {
	my($self) = @_;
	$self->{digest};
}

sub _shahex {
	my($self) = @_;
	join("", unpack("H*", $self->{digest}));
}

sub _shabase64 {
	my($self) = @_;
	my $b64 = pack("u", $self->{digest});
	$b64 =~ s/^.//mg;
	$b64 =~ s/\n//g;
	$b64 =~ tr|` -_|AA-Za-z0-9+/|;
	my $numpads = (3 - length($self->{digest}) % 3) % 3;
	$b64 =~ s/.{$numpads}$// if $numpads;
	$b64;
}

sub _shadsize {
	my($self) = @_;
	$self->{digestlen};
}

sub _shacpy {
	my($to, $from) = @_;
	$to->{alg} = $from->{alg};
	$to->{sha} = $from->{sha};
	$to->{H} = [@{$from->{H}}];
	$to->{block} = $from->{block};
	$to->{blockcnt} = $from->{blockcnt};
	$to->{blocksize} = $from->{blocksize};
	no integer; $to->{len} = $from->{len}; use integer;
	$to->{digestlen} = $from->{digestlen};
	$to;
}

sub _shadup {
	my($self) = @_;
	my($copy);
	_shacpy($copy, $self);
}

sub _shadump {
	my $file = shift || "-";
	my $self = shift;
	open(F, ">$file") or return;
	printf F "alg:%d\n", $self->{alg};
	printf F "H";
	for (@{$self->{H}}) { $_ &= $MAX32; printf F ":%08x", $_ }
	printf F "\n";
	printf F "block";
	my @c = unpack("C*", $self->{block});
	push(@c, 0x00) while scalar(@c) < 128;
	for (@c) { printf F ":%02x", $_ }
	printf F "\n";
	printf F "blockcnt:%u\n", $self->{blockcnt};
	no integer;
		printf F "lenhh:%lu\n", 0;
		printf F "lenhl:%lu\n", 0;
		printf F "lenlh:%lu\n", $self->{len} / $TWO32;
		printf F "lenll:%lu\n", $self->{len} % $TWO32;
	use integer;
	close(F);
	$self;
}

sub _match {
	my($fh, $tag) = @_;
	my @f;
	while (<$fh>) {
		s/\s+$//;
		next if (/^(#|$)/);
		@f = split(/:/);
		last;
	}
	shift(@f) eq $tag or return;
	return(@f);
}

sub _shaload {
	my $file = shift || "-";
	open(F, "<$file") or return;

	my @f = _match(*F, "alg") or return;
	my $self = _shaopen(shift(@f));

	@f = _match(*F, "H") or return;
	@{$self->{H}} = map { hex($_) } @f;

	@f = _match(*F, "block") or return;
	for (@f) { $self->{block} .= chr(hex($_)) }

	@f = _match(*F, "blockcnt") or return;
	$self->{blockcnt} = shift(@f);
	$self->{block} = substr($self->{block},0,_BYTECNT($self->{blockcnt}));

	@f = _match(*F, "lenhh") or return;
	@f = _match(*F, "lenhl") or return;
	@f = _match(*F, "lenlh") or return;
	no integer; $self->{len} = shift(@f) * $TWO32; use integer;
	@f = _match(*F, "lenll") or return;
	no integer; $self->{len} += shift(@f); use integer;

	close(F);
	$self;
}

# SHA functions

sub sha1 {
	my $state = _shaopen(1);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shadigest($state);
}

sub sha1_hex {
	my $state = _shaopen(1);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shahex($state);
}

sub sha1_base64 {
	my $state = _shaopen(1);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shabase64($state);
}

sub sha224 {
	my $state = _shaopen(224);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shadigest($state);
}

sub sha224_hex {
	my $state = _shaopen(224);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shahex($state);
}

sub sha224_base64 {
	my $state = _shaopen(224);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shabase64($state);
}

sub sha256 {
	my $state = _shaopen(256);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shadigest($state);
}

sub sha256_hex {
	my $state = _shaopen(256);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shahex($state);
}

sub sha256_base64 {
	my $state = _shaopen(256);
	for (@_) { _shawrite($_, length($_) << 3, $state) }
	_shafinish($state);
	_shabase64($state);
}

# ref. src/hmac.c from Digest::SHA

sub _hmacopen {
	my($alg, $key) = @_;
	my($self);
	$self->{isha} = _shaopen($alg) or return;
	$self->{osha} = _shaopen($alg) or return;
	if (length($key) > 64) {
		$self->{ksha} = _shaopen($alg) or return;
		_shawrite($key, length($key) << 3, $self->{ksha});
		_shafinish($self->{ksha});
		$key = _shadigest($self->{ksha});
	}
	$key .= chr(0x00) while length($key) < 64;
	my @k = unpack("C*", $key);
	for (@k) { $_ ^= 0x5c }
	_shawrite(pack("C*", @k), 512, $self->{osha});
	for (@k) { $_ ^= (0x5c ^ 0x36) }
	_shawrite(pack("C*", @k), 512, $self->{isha});
	$self;
}

sub _hmacwrite {
	my($bitstr, $bitcnt, $self) = @_;
	_shawrite($bitstr, $bitcnt, $self->{isha});
}

sub _hmacfinish {
	my($self) = @_;
	_shafinish($self->{isha});
	_shawrite(_shadigest($self->{isha}),
			$self->{isha}->{digestlen} << 3, $self->{osha});
	_shafinish($self->{osha});
}

sub _hmacdigest {
	my($self) = @_;
	_shadigest($self->{osha});
}

sub _hmachex {
	my($self) = @_;
	_shahex($self->{osha});
}

sub _hmacbase64 {
	my($self) = @_;
	_shabase64($self->{osha});
}

# HMAC-SHA functions

sub hmac_sha1 {
	my $state = _hmacopen(1, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacdigest($state);
}

sub hmac_sha1_hex {
	my $state = _hmacopen(1, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmachex($state);
}

sub hmac_sha1_base64 {
	my $state = _hmacopen(1, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacbase64($state);
}

sub hmac_sha224 {
	my $state = _hmacopen(224, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacdigest($state);
}

sub hmac_sha224_hex {
	my $state = _hmacopen(224, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmachex($state);
}

sub hmac_sha224_base64 {
	my $state = _hmacopen(224, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacbase64($state);
}

sub hmac_sha256 {
	my $state = _hmacopen(256, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacdigest($state);
}

sub hmac_sha256_hex {
	my $state = _hmacopen(256, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmachex($state);
}

sub hmac_sha256_base64 {
	my $state = _hmacopen(256, pop(@_));
	for (@_) { _hmacwrite($_, length($_) << 3, $state) }
	_hmacfinish($state);
	_hmacbase64($state);
}

# OO methods

sub hashsize {
	my $self = shift;
	_shadsize($self) << 3;
}

sub algorithm {
	my $self = shift;
	$self->{alg};
}

sub add {
	my $self = shift;
	for (@_) { _shawrite($_, length($_) << 3, $self) }
	$self;
}

sub digest {
	my $self = shift;
	_shafinish($self);
	my $rsp = _shadigest($self);
	_sharewind($self);
	$rsp;
}

sub _hexdigest {
	my $self = shift;
	_shafinish($self);
	my $rsp = _shahex($self);
	_sharewind($self);
	$rsp;
}

sub _b64digest {
	my $self = shift;
	_shafinish($self);
	my $rsp = _shabase64($self);
	_sharewind($self);
	$rsp;
}

sub new {
	my($class, $alg) = @_;
	$alg =~ s/\D+//g if defined $alg;
	if (ref($class)) {	# instance method
		unless (defined($alg) && ($alg != $class->algorithm)) {
			_sharewind($class);
			return($class);
		}
		my $self = _shaopen($alg) or return;
		return(_shacpy($class, $self));
	}
	$alg = 1 unless defined $alg;
	my $self = _shaopen($alg) or return;
	bless($self, $class);
	$self;
}

sub clone {
	my $self = shift;
	my $copy = _shadup($self) or return;
	bless($copy, ref($self));
	return($copy);
}

*reset = \&new;

sub add_bits {
	my($self, $data, $nbits) = @_;
	unless (defined $nbits) {
		$nbits = length($data);
		$data = pack("B*", $data);
	}
	_shawrite($data, $nbits, $self);
	return($self);
}

# local copy of "addfile" in case Digest::base not installed

sub _addfile {	# this is "addfile" from Digest::base 1.00
    my ($self, $handle) = @_;

    my $n;
    my $buf = "";

    while (($n = read($handle, $buf, 4096))) {
	$self->add($buf);
    }
    unless (defined $n) {
	require Carp;
	Carp::croak("Read failed: $!");
    }

    $self;
}

sub dump {
	my $self = shift;
	my $file = shift || "";

	_shadump($file, $self) or return;
	return($self);
}

sub load {
	my $class = shift;
	my $file = shift || "";
	if (ref($class)) {	# instance method
		my $self = _shaload($file) or return;
		return(_shacpy($class, $self));
	}
	my $self = _shaload($file) or return;
	bless($self, $class);
	return($self);
}

1;
__END__

=head1 NAME

Digest::SHA::PurePerl - Perl implementation of SHA-1/224/256

=head1 SYNOPSIS (SHA)

 # Functional style
 use Digest::SHA::PurePerl qw(sha1 sha1_hex sha1_base64 sha256 ... );

 $digest = sha1($data);
 $digest = sha1_hex($data);
 $digest = sha1_base64($data);


 # OO style
 use Digest::SHA::PurePerl;

 $sha = Digest::SHA::PurePerl->new($alg);	# alg = 1, 224, 256

 $sha->add($data);
 $sha->addfile(*FILE);

 $digest = $sha->digest;
 $digest = $sha->hexdigest;
 $digest = $sha->b64digest;

 $sha->add_bits($bits);			# bitwise inputs
 $sha->add_bits($data, $nbits);

 $sha->dump($filename);			# save/restore SHA states
 $sha->load($filename);

=head1 SYNOPSIS (HMAC-SHA)

 # Functional style only
 use Digest::SHA::PurePerl qw(hmac_sha1 hmac_sha1_hex ... );

 $digest = hmac_sha1($data, $key);
 $digest = hmac_sha1_hex($data, $key);
 $digest = hmac_sha1_base64($data, $key);

 $digest = hmac_sha256($data, $key);
 $digest = hmac_sha256_hex($data, $key);
 $digest = hmac_sha256_base64($data, $key);

=head1 ABSTRACT

Digest::SHA::PurePerl is a pure Perl implementation of the SHA-1,
SHA-224, and SHA-256 algorithms of the NIST Secure Hash Standard.
A C compiler is not needed to use this module.

Those who do have a C compiler are B<STRONGLY> urged to use the
Digest::SHA module instead.  The latter module is much faster, and
also includes support for the SHA-384 and SHA-512 algorithms.

=head1 DESCRIPTION

Digest::SHA::PurePerl implements the most commonly-used hashing
algorithms of the SHA standard (NIST FIPS PUB 180-2).  It offers
two ways to calculate digests: all-at-once, or in stages.

To illustrate, the following short program computes the SHA-256
digest of "hello world" using each approach:

	use Digest::SHA::PurePerl qw(sha256_hex);

	$data = "hello world";
	@frags = split(//, $data);

	# all-at-once (Functional style)
	$digest1 = sha256_hex($data);

	# in-stages (OO style)
	$state = Digest::SHA::PurePerl->new(256);
	for (@frags) { $state->add($_) }
	$digest2 = $state->hexdigest;

	print $digest1 eq $digest2 ?
		"whew!\n" : "career in aluminum siding\n";

To calculate the digest of an n-bit message where I<n> is not a
multiple of 8, use the I<add_bits()> method.  For example, consider
the 446-bit message consisting of the bit-string "110" repeated
148 times, followed by "11".  Here's how to calculate its SHA-1
digest:

	use Digest::SHA::PurePerl;
	$bits = "110" x 148 . "11";
	$digest = Digest::SHA::PurePerl->new(1)->add_bits($bits)->hexdigest;

Note that for larger bit-strings, it's more efficient to use the
two-argument version I<add_bits($data, $nbits)>, where I<$data> is
in the customary packed binary format used for Perl strings.

The module also lets you save intermediate SHA states to disk, or
display them on standard output.  The I<dump()> method generates
a portable, human-readable text-file describing the current state
of computation.  You can subsequently retrieve the file with
I<load()> to resume where the calculation left off.

If you're curious about what a state description looks like, just
run the following:

	use Digest::SHA::PurePerl;
	Digest::SHA::PurePerl->new(256)->add("COL Bat Guano" x 1964)->dump;

As an added convenience, the Digest::SHA::PurePerl module offers
routines to calculate keyed hashes using the HMAC-SHA-1/224/256
algorithms.  These services exist in functional form only, and
mimic the style and behavior of the I<sha()>, I<sha_hex()>, and
I<sha_base64()> functions.

	# test vector from draft-ietf-ipsec-ciph-sha-256-01.txt

	use Digest::SHA::PurePerl qw(hmac_sha256_hex);
	print hmac_sha256_hex("Hi There", chr(0x0b) x 32), "\n";

=head1 EXPORT

None by default.

=head1 EXPORTABLE FUNCTIONS

I<Functional style>

=over 4

=item B<sha1($data, ...)>

=item B<sha224($data, ...)>

=item B<sha256($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/224/256 digest encoded as a binary string.

=item B<sha1_hex($data, ...)>

=item B<sha224_hex($data, ...)>

=item B<sha256_hex($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/224/256 digest encoded as a hexadecimal string.

=item B<sha1_base64($data, ...)>

=item B<sha224_base64($data, ...)>

=item B<sha256_base64($data, ...)>

Logically joins the arguments into a single string, and returns
its SHA-1/224/256 digest encoded as a Base64 string.

=back

I<OO style>

=over 4

=item B<new($alg)>

Returns a new Digest::SHA::PurePerl object.  Values for I<$alg>
are 1, 224, or 256.  It's also possible to use common string
representations of the algorithm (e.g. "sha256", "SHA-224").  If
the argument is missing, SHA-1 will be used by default.

Invoking I<new> as an instance method will not create a new object;
instead, it will simply reset the object to the initial state
associated with I<$alg>.  If the argument is missing, the object
will continue using the same algorithm that was selected at creation.

=item B<reset($alg)>

This method has exactly the same effect as I<new($alg)>.  In fact,
I<reset> is just an alias for I<new>.

=item B<hashsize>

Returns the number of digest bits for this object.  The values are
160, 224, and 256 for SHA-1, SHA-224, and SHA-256, respectively.

=item B<algorithm>

Returns the digest algorithm for this object.  The values are 1,
224, and 256 for SHA-1, SHA-224, and SHA-256, respectively.

=item B<clone>

Returns a duplicate copy of the object.

=item B<add($data, ...)>

Logically joins the arguments into a single string, and uses that
string to update the current digest state.  In other words, the
following statements have the same effect:

	$sha->add("a"); $sha->add("b"); $sha->add("c");
	$sha->add("a")->add("b")->add("c");
	$sha->add("a", "b", "c");
	$sha->add("abc");

The return value is the updated object itself.

=item B<add_bits($data, $nbits)>

=item B<add_bits($bits)>

Updates the current digest state by appending bits to it.  The
return value is the updated object itself.

The first form causes the most-significant I<$nbits> of I<$data>
to be appended to the stream.  The I<$data> argument is in the
customary binary format used for Perl strings.

The second form takes an ASCII string of "0" and "1" characters as
its argument.  It's equivalent to

	$sha->add_bits(pack("B*", $bits), length($bits));

So, the following two statements do the same thing:

	$sha->add_bits("111100001010");
	$sha->add_bits("\xF0\xA0", 12);

=item B<addfile(*FILE)>

Reads from I<FILE> until EOF, and appends that data to the current
state.  The return value is the updated object itself.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=item B<dump($filename)>

Provides persistent storage of intermediate SHA states by writing
a portable, human-readable representation of the current state to
I<$filename>.  If the argument is missing, or equal to the empty
string, the state information will be written to STDOUT.

=item B<load($filename)>

Returns a Digest::SHA::PurePerl object representing the intermediate
SHA state that was previously stored to I<$filename>.  If called
as a class method, a new object is created; if called as an instance
method, the object is reset to the state contained in I<$filename>.
If the argument is missing, or equal to the empty string, the state
information will be read from STDIN.

=item B<digest>

Returns the digest encoded as a binary string.

Note that the I<digest> method is a read-once operation. Once it
has been performed, the Digest::SHA::PurePerl object is automatically
reset in preparation for calculating another digest value.  Call
I<$sha-E<gt>clone-E<gt>digest> if it's necessary to preserve the
original digest state.

=item B<hexdigest>

Returns the digest encoded as a hexadecimal string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>hexdigest> if it's necessary to preserve
the original digest state.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=item B<b64digest>

Returns the digest encoded as a Base64 string.

Like I<digest>, this method is a read-once operation.  Call
I<$sha-E<gt>clone-E<gt>b64digest> if it's necessary to preserve
the original digest state.

This method is inherited if L<Digest::base> is installed on your
system.  Otherwise, a functionally equivalent substitute is used.

=back

I<HMAC-SHA-1/224/256>

=over 4

=item B<hmac_sha1($data, $key)>

=item B<hmac_sha224($data, $key)>

=item B<hmac_sha256($data, $key)>

Returns the HMAC-SHA-1/224/256 digest of I<$data>/I<$key>, with
the result encoded as a binary string.  Multiple I<$data> arguments
are allowed, provided that I<$key> is the last argument in the
list.

=item B<hmac_sha1_hex($data, $key)>

=item B<hmac_sha224_hex($data, $key)>

=item B<hmac_sha256_hex($data, $key)>

Returns the HMAC-SHA-1/224/256 digest of I<$data>/I<$key>, with
the result encoded as a hexadecimal string.  Multiple I<$data>
arguments are allowed, provided that I<$key> is the last argument
in the list.

=item B<hmac_sha1_base64($data, $key)>

=item B<hmac_sha224_base64($data, $key)>

=item B<hmac_sha256_base64($data, $key)>

Returns the HMAC-SHA-1/224/256 digest of I<$data>/I<$key>, with
the result encoded as a Base64 string.  Multiple I<$data> arguments
are allowed, provided that I<$key> is the last argument in the
list.

=back

=head1 SEE ALSO

L<Digest>, L<Digest::SHA>, L<Digest::SHA1>, L<Digest::SHA2>

The Secure Hash Standard (FIPS PUB 180-2) can be found at:

L<http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf>

The Keyed-Hash Message Authentication Code (HMAC):

L<http://csrc.nist.gov/publications/fips/fips198/fips-198a.pdf>

=head1 AUTHOR

Mark Shelor, E<lt>mshelor@comcast.netE<gt>

The author is particularly grateful to Gisle Ass, Julius Duque,
Jeffrey Friedl, Robert Gilmour, Brian Gladman, Andy Lester, Alex
Muntada, Chris Skiscim, and Martin Thurn for their valuable comments,
suggestions, and technical support.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2003-2004 Mark Shelor

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

L<perlartistic>

=cut

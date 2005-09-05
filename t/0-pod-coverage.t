use Test::More;
eval "use Test::Pod::Coverage 0.08";
plan skip_all => "Test::Pod::Coverage 0.08 required for testing POD coverage" if $@;

my @privfcns = qw(
);

all_pod_coverage_ok( { also_private => \@privfcns } );

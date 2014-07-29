# Run some basic tests to check the randomness.
# Success implies little, but failure establishes that the PRG
# is unsuitable for cryptographic purposes.

use strict;
use warnings;
use Win32::GenRandom qw(:all);

eval {require Math::GMPz;};

if($@) {
  print "1..1\n";
  warn "\nMath::GMPz could not be loaded - skipping all tests\n";
  print "ok 1\n";

}
else {

  print "1..2\n";
  my $count = 210;

  my $z = Math::GMPz->new('1' x 20000, 2);

  my ($major, $minor) = (Win32::GetOSVersion())[1, 2];

  my @cgr;
  my @rgr;

  push @cgr, cgr(1, 2500) for 1 .. $count;
  push @rgr, rgr(1, 2500) for 1 .. $count;

  die "Wrong number of random strings in \@cgr" unless @cgr == $count;
  die "Wrong number of random strings in \@rgr" unless @rgr == $count;

  my $ok = 'abcd';

  for(@cgr) {
    Math::GMPz::Rmpz_set_str($z, unpack("b*", $_), 2);
    unless(Math::GMPz::Rmonobit($z)) {
      $ok =~ s/a//;
      warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
    }
    unless(Math::GMPz::Rlong_run($z)) {
      $ok =~ s/b//;
      warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
    }
    unless(Math::GMPz::Rruns($z)) {
      $ok =~ s/c//;
      warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
    }
    unless(Math::GMPz::Rpoker($z)) {
      $ok =~ s/d//;
      warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
    }
  }

  if($ok eq 'abcd') {print "ok 1\n"}
  else {
    warn "\$ok: $ok\n";
    print "not ok 1\n";
  }

  if($major == 5 && $minor == 0) {
    print "\nSkipping test 2 - RtlGenRandom() not available on this system\n";
    print "ok 2\n";
  }
  else {
    $ok = 'abcd';

    for(@rgr) {
      Math::GMPz::Rmpz_set_str($z, unpack("b*", $_), 2);
      unless(Math::GMPz::Rmonobit($z)) {
        $ok =~ s/a//;
        warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
      }
      unless(Math::GMPz::Rlong_run($z)) {
        $ok =~ s/b//;
        warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
      }
      unless(Math::GMPz::Rruns($z)) {
        $ok =~ s/c//;
        warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
      }
      unless(Math::GMPz::Rpoker($z)) {
        $ok =~ s/d//;
        warn Math::GMPz::Rmpz_get_str($z, 62), "\n";
      }
    }

    if($ok eq 'abcd') {print "ok 2\n"}
    else {
      warn "\$ok: $ok\n";
      print "not ok 2\n";
    }
  }
}

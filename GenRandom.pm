## This file generated by InlineX::C2XS (version 0.22) using Inline::C (version 0.55)
package Win32::GenRandom;
use strict;
use warnings;
use Config;
use Win32;

require Exporter;
*import = \&Exporter::import;
require DynaLoader;

$Win32::GenRandom::VERSION = '0.04';

DynaLoader::bootstrap Win32::GenRandom $Win32::GenRandom::VERSION;

use subs qw(
    PROV_FORTEZZA CRYPT_VERIFYCONTEXT CRYPT_DELETEKEYSET PROV_SSL PROV_RSA_SIG PROV_DSS
    CRYPT_NEWKEYSET PROV_DH_SCHANNEL CRYPT_MACHINE_KEYSET CRYPT_DEFAULT_CONTAINER_OPTIONAL
    PROV_MS_EXCHANGE PROV_RSA_FULL PROV_RSA_AES CRYPT_SILENT PROV_RSA_SCHANNEL PROV_DSS_DH
           );

@Win32::GenRandom::EXPORT = ();
@Win32::GenRandom::EXPORT_OK = qw(
    cgr rgr cgr_uv rgr_uv cgr_32 rgr_32 gr gr_uv gr_32 cgr_custom cgr_custom_uv cgr_custom_32
    which_crypto
    PROV_FORTEZZA CRYPT_VERIFYCONTEXT CRYPT_DELETEKEYSET PROV_SSL PROV_RSA_SIG PROV_DSS
    CRYPT_NEWKEYSET PROV_DH_SCHANNEL CRYPT_MACHINE_KEYSET CRYPT_DEFAULT_CONTAINER_OPTIONAL
    PROV_MS_EXCHANGE PROV_RSA_FULL PROV_RSA_AES CRYPT_SILENT PROV_RSA_SCHANNEL PROV_DSS_DH
    );

%Win32::GenRandom::EXPORT_TAGS = (all => [qw(
    cgr rgr cgr_uv rgr_uv cgr_32 rgr_32 gr gr_uv gr_32 cgr_custom cgr_custom_uv cgr_custom_32
    which_crypto
    PROV_FORTEZZA CRYPT_VERIFYCONTEXT CRYPT_DELETEKEYSET PROV_SSL PROV_RSA_SIG PROV_DSS
    CRYPT_NEWKEYSET PROV_DH_SCHANNEL CRYPT_MACHINE_KEYSET CRYPT_DEFAULT_CONTAINER_OPTIONAL
    PROV_MS_EXCHANGE PROV_RSA_FULL PROV_RSA_AES CRYPT_SILENT PROV_RSA_SCHANNEL PROV_DSS_DH
    )]);

my ($major, $minor) = (Win32::GetOSVersion())[1, 2];

$Win32::GenRandom::rtl_avail = ($major == 5 && $minor == 0) || $major < 5 ? 0 : 1;

sub cgr_uv {
  my @cgr;
  if(@_) {
    @cgr = cgr($_[0], $Config::Config{ivsize});
    return map {scalar(reverse(unpack "J", $_))} @cgr;
  }
  @cgr = cgr($Config::Config{ivsize});
  return scalar reverse(unpack "J", $cgr[0]);
}

sub rgr_uv {
  my @rgr;
  if(@_) {
    @rgr = rgr($_[0], $Config::Config{ivsize});
    return map {scalar(reverse(unpack "J", $_))} @rgr;
  }
  @rgr = rgr($Config::Config{ivsize});
  return scalar reverse(unpack "J", $rgr[0]);
}

sub cgr_32 {
  my @cgr;
  if(@_) {
    @cgr = cgr($_[0], 4);
    return map {scalar(reverse(unpack "L", $_))} @cgr;
  }
  @cgr = cgr(4);
  return scalar reverse(unpack "L", $cgr[0]);
}

sub rgr_32 {
  my @rgr;
  if(@_) {
    @rgr = rgr($_[0], 4);
    return map {scalar(reverse(unpack "L", $_))} @rgr;
  }
  @rgr = rgr(4);
  return scalar reverse(unpack "L", $rgr[0]);
}

sub gr {
  return rgr(@_) if $Win32::GenRandom::rtl_avail;
  return cgr(@_);
}

sub gr_uv {
  return rgr_uv(@_) if $Win32::GenRandom::rtl_avail;
  return cgr_uv(@_);
}

sub gr_32 {
  return rgr_32(@_) if $Win32::GenRandom::rtl_avail;
  return cgr_32(@_);
}

sub cgr_custom_uv {
  my @cgr;
  if(@_ == 5) {
    @cgr = cgr_custom($_[0], $Config::Config{ivsize}, $_[1], $_[2], $_[3], $_[4]);
    return map {scalar(reverse(unpack "J", $_))} @cgr;
  }
  @cgr = cgr_custom($Config::Config{ivsize}, $_[0], $_[1], $_[2], $_[3]);
  return scalar reverse(unpack "J", $cgr[0]);
}

sub cgr_custom_32 {
  my @cgr;
  if(@_ == 5) {
    @cgr = cgr_custom($_[0], 4, $_[1], $_[2], $_[3], $_[4]);
    return map {scalar(reverse(unpack "L", $_))} @cgr;
  }
  @cgr = cgr_custom(4, $_[0], $_[1], $_[2], $_[3]);
  return scalar reverse(unpack "L", $cgr[0]);
}

sub which_crypto {
  $Win32::GenRandom::rtl_avail ? 'RtlGenRandom' : 'CryptGenRandom';
}

sub _system_error {
   warn "$^E";
}

sub PROV_FORTEZZA {return _PROV_FORTEZZA()}
sub CRYPT_VERIFYCONTEXT {return _CRYPT_VERIFYCONTEXT()}
sub CRYPT_DELETEKEYSET {return _CRYPT_DELETEKEYSET()}
sub PROV_SSL {return _PROV_SSL()}
sub PROV_RSA_SIG {return _PROV_RSA_SIG()}
sub PROV_DSS {return _PROV_DSS()}
sub CRYPT_NEWKEYSET {return _CRYPT_NEWKEYSET()}
sub PROV_DH_SCHANNEL {return _PROV_DH_SCHANNEL()}
sub CRYPT_MACHINE_KEYSET {return _CRYPT_MACHINE_KEYSET()}
sub CRYPT_DEFAULT_CONTAINER_OPTIONAL {return _CRYPT_DEFAULT_CONTAINER_OPTIONAL()}
sub PROV_MS_EXCHANGE {return _PROV_MS_EXCHANGE()}
sub PROV_RSA_FULL {return _PROV_RSA_FULL()}
sub PROV_RSA_AES {return _PROV_RSA_AES()}
sub CRYPT_SILENT {return _CRYPT_SILENT()}
sub PROV_RSA_SCHANNEL {return _PROV_RSA_SCHANNEL()}
sub PROV_DSS_DH {return _PROV_DSS_DH()}

sub dl_load_flags {0} # Prevent DynaLoader from complaining and croaking

1;

__END__

=head1 NAME

   Win32::GenRandom - XS wrappers of CryptGenRandom and RtlGenRandom.

=head1 FUNCTIONS

   @c = cgr($how_many, $size); # 1st arg is optional

    Returns a list of $how_many strings - each string consisting of
    $size random bytes.
    Returns just one string if the $how_many is not specified - in which
    case the function may be called either as:
      $c = cgr($size);
      or
      @c = cgr($size);
    This function uses CryptGenRandom to generate the random strings.

   @c = rgr($how_many, $size); # 1st arg is optional

    As for cgr() - but uses RtlGenRandom instead of CryptGenRandom
    to generate the random strings.
    (Not available on Windows 2000 and earlier - croaks if used on
    such a system.)

   @c = gr($how_many, $size); # $how_many is an optional arg.

    As for cgr() and rgr() - but returns rgr(@_) if
    $Win32::GenRandom::rtl_avail is true (ie if RtlGenRandom is
    available); otherwise returns cgr(@_).

   @c = cgr_uv($how_many); # $how_many is an optional arg.

    Returns a list of $how_many Perl internal unsigned integer
    values (UV). Whether the returned values are 32-bit or 64-bit
    depends upon your perl configuration.
    Returns just one UV if $how_many is not specified - in which
    case the function may be called either as:
      $c = cgr_uv();
      or
      @c = cgr_uv();
    This function uses CryptGenRandom to generate the random UVs.

   @c = rgr_uv($how_many); # $how_many is an optional arg.

    As for cgr_uv() - but uses RtlGenRandom instead of CryptGenRandom
    to generate the random UVs.
    (Not available on Windows 2000 and earlier - croaks if used on
    such a system.)

   @c = gr_uv($how_many); # $how_many is an optional arg.

    As for cgr_uv() and rgr_uv) - but returns rgr_uv() if
    $Win32::GenRandom::rtl_avail is true (ie if RtlGenRandom is
    available); otherwise returns cgr_uv(@_).

   @c = cgr_32($how_many); # $how_many is an optional arg.

    Returns a list of $how_many 32-bit unsigned integer values.
    Returns just one integer if $how_many is not specified - in
    which case the function may be called either as:
      $c = cgr_32();
      or
      @c = cgr_32();
    This function uses CryptGenRandom to generate the random UVs.

   @c = rgr_32($how_many); # $how_many is an optional arg.

    As for cgr_32() - but uses RtlGenRandom instead of CryptGenRandom
    to generate the random 32-bit values.
    (Not available on Windows 2000 and earlier - croaks if used on
    such a system.)

   @c = gr_32($how_many); # $how_many is an optional arg.

    As for cgr_32() and rgr_32() - but returns rgr_32(@_) if
    $Win32::GenRandom::rtl_avail is true (ie if RtlGenRandom is
    available); otherwise returns cgr_32(@_).

   @c = cgr_custom($how_many, $size, $container, $prov, $type, $flags);
   @c = cgr_custom_uv($how_many, $container, $prov, $type, $flags);
   @c = cgr_custom_32($how_many, $container, $prov, $type, $flags);

    Again, $how_many is optional and, if absent, defaults to 1 - in
    which case the returned value can be assigned to either a scalar
    or an array.
    These functions are the same as cgr(), cgr_uv() and cgr_32(), but
    they allow the user to specify the args that CryptAcquireContextA
    takes, instead of forcing the user to accept the defaults that
    cgr(), cgr_uv() and cgr_32() provide.
    $container is the key container name (string). Provide the empty
    string if you don't want to specify a particular value.
    $prov is the name (string) of the Cryptographic Service Provider to
    be used. Specify the empty string if you don't want to specify a
    particular CSP.
    $type specifies the type of provider to acquire.
    $flags is, as the name suggests, the flag value to be used.
    For your convenience, the allowed Type and Flag constants provided
    by wincrypt.h have been wrapped in perl subs of the same name - see
    the CONSTANTS section below.
    See the MSDN docs for CryptAcquireContext for more info.

   $which = which_crypto();

    Returns 'RtlGenRandom' if $Win32::GenRandom::rtl_avail is true;
    otherwise returns 'CryptGenRandom'.
    IOW it tells us which crypto functionality the "gr" functions will
    use - and is just another way to access the value of
    $Win32::GenRandom::rtl_avail (via subroutine call).

=head1 CONSTANTS

    The following subroutines return the same value as that defined by
    their name in wincrypt.h:
     PROV_FORTEZZA
     PROV_RSA_SCHANNEL
     PROV_DSS_DH
     PROV_SSL
     PROV_RSA_SIG
     PROV_DSS
     PROV_MS_EXCHANGE
     PROV_RSA_FULL
     PROV_RSA_AES
     PROV_DH_SCHANNEL
     CRYPT_VERIFYCONTEXT
     CRYPT_DELETEKEYSET
     CRYPT_NEWKEYSET
     CRYPT_MACHINE_KEYSET
     CRYPT_DEFAULT_CONTAINER_OPTIONAL
     CRYPT_SILENT

=head1 LICENSE

    This program is free software; you may redistribute it and/or
    modify it under the same terms as Perl itself.
    Copyright 2014 Sisyphus

=head1 AUTHOR

    Sisyphus <sisyphus at(@) cpan dot (.) org>

=cut

#define PERL_NO_GET_CONTEXT 1

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"


#include <wincrypt.h> /* needed for crypt_gen_random()
                         but not for rtl_gen_random() */

void print_error(pTHX) {

  dSP;
  PUSHMARK(SP);
  call_pv("Win32::GenRandom::_system_error", G_DISCARD|G_NOARGS);
}

void cgr(pTHX_ unsigned long how_many, unsigned long len) {

  dXSARGS;
  int i;
  char * buff;
  HCRYPTPROV prov = 0;

  if(!CryptAcquireContextA(&prov, 0, 0, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT)) {
    print_error(aTHX); /* callback to $^E */
    croak("Call to CryptAcquireContextA() failed");
  }

  Newx(buff, len, char);
  if(buff == NULL) {
    CryptReleaseContext(prov, 0);
    croak ("Failed to allocate memory for buffer");
  }

  for(i = 0; i < how_many; i++) {
    if(!CryptGenRandom(prov, len, buff)) {
      Safefree(buff);
      CryptReleaseContext(prov, 0);
      print_error(aTHX); /* callback to $^E */
      croak("Call to CryptGenRandom() failed");
    }

    ST(i) = sv_2mortal(newSVpv(buff, len));
  }
  Safefree(buff);
  CryptReleaseContext(prov, 0);
  XSRETURN(how_many);
}

void rgr(pTHX_ unsigned long how_many, unsigned long len) {
#ifndef WIN2K
  dXSARGS;
  int i;
  char * buff;

  Newx(buff, len, char);
  if(buff == 0) croak ("Failed to allocate memory for 'buff'");

  HMODULE hLib=LoadLibrary("ADVAPI32.DLL");

  if (hLib) {
    BOOLEAN (APIENTRY *pfn)(void*, ULONG) =
      (BOOLEAN (APIENTRY *)(void*,ULONG))GetProcAddress(hLib,"SystemFunction036");

    for(i = 0; i < how_many; i++) {
      if(pfn(buff,len)) ST(i) = sv_2mortal(newSVpv(buff, len));
      else {
        FreeLibrary(hLib);
        print_error(aTHX); /* callback to $^E */
        croak("Call to 'SystemFunction036' failed");
      }
    }

    FreeLibrary(hLib);
  }

  else {
    print_error(aTHX); /* callback to $^E */
    croak("Failed to load ADVAPI32.dll");
  }

  Safefree(buff);
  XSRETURN(how_many);

# else
  croak("RtlGenRandom() not available on Windows 2000 - use CryptGenRandom() instead");
#endif

}

SV * _error_test(pTHX) {
  /* Solely for use of test suite */
  HMODULE hLib=LoadLibrary("NO_SUCH.DLL");
  if(hLib) return newSVuv(0);
  else print_error(aTHX);
  return newSVuv(42);
}

MODULE = Win32::GenRandom	PACKAGE = Win32::GenRandom

PROTOTYPES: DISABLE


void
print_error ()

	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	print_error(aTHX);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

void
cgr (how_many, len)
	unsigned long	how_many
	unsigned long	len
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	cgr(aTHX_ how_many, len);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

void
rgr (how_many, len)
	unsigned long	how_many
	unsigned long	len
	PREINIT:
	I32* temp;
	PPCODE:
	temp = PL_markstack_ptr++;
	rgr(aTHX_ how_many, len);
	if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
	  PL_markstack_ptr = temp;
	  XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
	return; /* assume stack size is correct */

SV *
_error_test ()
CODE:
  RETVAL = _error_test (aTHX);
OUTPUT:  RETVAL



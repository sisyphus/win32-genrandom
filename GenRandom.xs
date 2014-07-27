
#ifdef  __MINGW32__
#ifndef __USE_MINGW_ANSI_STDIO
#define __USE_MINGW_ANSI_STDIO 1
#endif
#endif

#define PERL_NO_GET_CONTEXT 1

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "INLINE.h"

#include <wincrypt.h> /* needed for crypt_gen_random()
                         but not for rtl_gen_random() */

void print_error(pTHX) {

  dSP;
  PUSHMARK(SP);
  call_pv("Win32::GenRandom::_system_error", G_DISCARD|G_NOARGS);
}

void cgr(pTHX_ SV * quantity, SV * l) {

  dXSARGS;
  unsigned long i;
  BYTE * buff;
  HCRYPTPROV prov = 0;
  unsigned long how_many = (unsigned long)SvUV(quantity);
  DWORD len =      (DWORD)SvIV(l);

  if(!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_SILENT | CRYPT_VERIFYCONTEXT)) {
    print_error(aTHX); /* callback to $^E */
    croak("Call to CryptAcquireContextA() failed");
  }

  Newx(buff, len + 1, BYTE);
  if(buff == NULL) {
    warn ("Failed to allocate memory for buffer");
    CryptReleaseContext(prov, 0);
    croak("Croaking - owing to memory allocation failure");
  }

  for(i = 0; i < how_many; i++) {
    if(!CryptGenRandom(prov, len, buff)) {
      warn("Call to CryptGenRandom failed");
      Safefree(buff);
      CryptReleaseContext(prov, 0);
      print_error(aTHX); /* callback to $^E */
      croak("Croaking - owing to failure of call to CryptGenRandom");
    }
    ST(i) = sv_2mortal(newSVpv(buff, len));
  }
  Safefree(buff);
  CryptReleaseContext(prov, 0);
  XSRETURN(how_many);
}

void rgr(pTHX_ SV * quantity, SV * l) {
#ifndef WIN2K
  dXSARGS;
  unsigned long i;
  BYTE * buff;
  unsigned long how_many = (unsigned long)SvUV(quantity);
  ULONG len =      (ULONG)SvUV(l);
  HMODULE hLib;

  Newx(buff, len + 1, BYTE);
  if(buff == NULL) croak ("Failed to allocate memory for 'buff'");

  hLib = LoadLibrary("ADVAPI32.DLL");

  if (hLib) {
    BOOLEAN (APIENTRY *pfn)(void*, ULONG) =
      (BOOLEAN (APIENTRY *)(void*,ULONG))GetProcAddress(hLib,"SystemFunction036");

    for(i = 0; i < how_many; i++) {
      if(pfn(buff,len)) ST(i) = sv_2mortal(newSVpv(buff, len));
      else {
        warn("Call to 'SystemFunction036' failed");
        FreeLibrary(hLib);
        print_error(aTHX); /* callback to $^E */
        croak("Croaking - owing to failure of call to 'SystemFunction036'");
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
  croak("RtlGenRandom not available on Windows 2000 - use CryptGenRandom instead");
#endif

}

SV * _error_test(pTHX) {
  /* Solely for use of test suite */
  HMODULE hLib=LoadLibrary("NO_SUCH.DLL");
  if(hLib) return newSVuv(0);
  else print_error(aTHX);
  return newSVuv(42);
}

/*
DWORD WINAPI GetLastError(void);
HRESULT HRESULT_FROM_WIN32(DWORD x);

BOOL WINAPI CryptAcquireContext(
  _Out_  HCRYPTPROV *phProv,
  _In_   LPCTSTR pszContainer,
  _In_   LPCTSTR pszProvider,
  _In_   DWORD dwProvType,
  _In_   DWORD dwFlags
);

BOOL WINAPI CryptGenRandom(
  _In_     HCRYPTPROV hProv,
  _In_     DWORD dwLen,
  _Inout_  BYTE *pbBuffer
);

BOOLEAN RtlGenRandom(
  _Out_  PVOID RandomBuffer,
  _In_   ULONG RandomBufferLength
);

#define Inline_Stack_Vars dXSARGS
#define Inline_Stack_Items items
#define Inline_Stack_Item(x) ST(x)
#define Inline_Stack_Reset sp = mark
#define Inline_Stack_Push(x) XPUSHs(x)
#define Inline_Stack_Done PUTBACK
#define Inline_Stack_Return(x) XSRETURN(x)
#define Inline_Stack_Void XSRETURN(0)

*/

MODULE = Win32::GenRandom  PACKAGE = Win32::GenRandom

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
cgr (quantity, l)
	SV *	quantity
	SV *	l
        PREINIT:
        I32* temp;
        PPCODE:
        temp = PL_markstack_ptr++;
        cgr(aTHX_ quantity, l);
        if (PL_markstack_ptr != temp) {
          /* truly void, because dXSARGS not invoked */
          PL_markstack_ptr = temp;
          XSRETURN_EMPTY; /* return empty stack */
        }
        /* must have used dXSARGS; list context implied */
        return; /* assume stack size is correct */

void
rgr (quantity, l)
	SV *	quantity
	SV *	l
        PREINIT:
        I32* temp;
        PPCODE:
        temp = PL_markstack_ptr++;
        rgr(aTHX_ quantity, l);
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



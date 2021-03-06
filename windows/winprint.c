/*
 * Printing interface for PuTTY.
 */

#include "putty.h"
#include <winspool.h>

struct printer_enum_tag {
    int nprinters;
    DWORD enum_level;
    union {
	LPPRINTER_INFO_4 i4;
	LPPRINTER_INFO_5 i5;
    } info;
};

struct printer_job_tag {
    HANDLE hprinter;
};

/*
 * Windows clipboard support
 * Diomidis Spinellis, June 2003
 */
static char *clip_b, *clip_bp;		/* Buffer, pointer to buffer insertion point */
static size_t clip_bsiz, clip_remsiz;	/* Buffer, size, remaining size */
static size_t clip_total;		/* Total read */
char *PRINT_TO_CLIPBOARD_STRING = "Windows Clipboard";

#define CLIP_CHUNK 16384

static void clipboard_init(void)
{
	if (clip_b)
		sfree(clip_b);
	clip_bp = clip_b = smalloc(clip_remsiz = clip_bsiz = CLIP_CHUNK);
	clip_total = 0;
}

static void clipboard_data(void *buff,  int len)
{
	memcpy(clip_bp, buff, len);
	clip_remsiz -= len;
	clip_total += len;
	clip_bp += len;
	if (clip_remsiz < CLIP_CHUNK) {
		clip_b = srealloc(clip_b, clip_bsiz *= 2);
		clip_remsiz = clip_bsiz - clip_total;
		clip_bp = clip_b + clip_total;
	}
}

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

void clipboard_decode_and_copy(char *data, int len)
{
	char *decoded;
	HANDLE hglb;
	int bufsize;

	if (!OpenClipboard(NULL) || !EmptyClipboard())
		return;

	decoded = smalloc(((len + 3) / 4) * 3 + 1);
	Base64decode(decoded, data);
	bufsize = MultiByteToWideChar(CP_UTF8, 0, decoded, -1, NULL, 0) * 2;
	hglb = GlobalAlloc(GMEM_DDESHARE, bufsize);
	if (hglb != NULL) {
		MultiByteToWideChar(CP_UTF8, 0, decoded, -1, (LPWSTR)hglb, bufsize);
		SetClipboardData(CF_UNICODETEXT, hglb);
	}

	CloseClipboard();
	sfree(decoded);
}

static void clipboard_copy(void)
{
	HANDLE hglb;

	if (!OpenClipboard(NULL))
		return; // error("Unable to open the clipboard");
	if (!EmptyClipboard()) {
		CloseClipboard();
		return; // error("Unable to empty the clipboard");
	}

	hglb = GlobalAlloc(GMEM_DDESHARE, clip_total + 1);
	if (hglb == NULL) {
		CloseClipboard();
		return; // error("Unable to allocate clipboard memory");
	}
	memcpy(hglb, clip_b, clip_total);
	((char *)hglb)[clip_total] = '\0';
	SetClipboardData(CF_TEXT, hglb);
	CloseClipboard();
}

/***/
static int printer_add_enum(int param, DWORD level, char **buffer,
                            int offset, int *nprinters_ptr)
{
    DWORD needed = 0, nprinters = 0;

    *buffer = sresize(*buffer, offset+512, char);

    /*
     * Exploratory call to EnumPrinters to determine how much space
     * we'll need for the output. Discard the return value since it
     * will almost certainly be a failure due to lack of space.
     */
    EnumPrinters(param, NULL, level, (LPBYTE) ((*buffer)+offset), 512,
		 &needed, &nprinters);

    if (needed < 512)
        needed = 512;

    *buffer = sresize(*buffer, offset+needed, char);

    if (EnumPrinters(param, NULL, level, (LPBYTE) ((*buffer)+offset),
                     needed, &needed, &nprinters) == 0)
        return FALSE;

    *nprinters_ptr += nprinters;

    return TRUE;
}

printer_enum *printer_start_enum(int *nprinters_ptr)
{
    printer_enum *ret = snew(printer_enum);
    char *buffer = NULL;

    *nprinters_ptr = 0;		       /* default return value */
    buffer = snewn(512, char);

    /*
     * Determine what enumeration level to use.
     * When enumerating printers, we need to use PRINTER_INFO_4 on
     * NT-class systems to avoid Windows looking too hard for them and
     * slowing things down; and we need to avoid PRINTER_INFO_5 as
     * we've seen network printers not show up.
     * On 9x-class systems, PRINTER_INFO_4 isn't available and
     * PRINTER_INFO_5 is recommended.
     * Bletch.
     */
    if (osVersion.dwPlatformId != VER_PLATFORM_WIN32_NT) {
	ret->enum_level = 5;
    } else {
	ret->enum_level = 4;
    }

    if (!printer_add_enum(PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
                          ret->enum_level, &buffer, 0, nprinters_ptr))
        goto error;

    switch (ret->enum_level) {
      case 4:
	ret->info.i4 = (LPPRINTER_INFO_4)buffer;
	break;
      case 5:
	ret->info.i5 = (LPPRINTER_INFO_5)buffer;
	break;
    }
    ret->nprinters = *nprinters_ptr;
    
    return ret;

    error:
    sfree(buffer);
    sfree(ret);
    *nprinters_ptr = 0;
    return NULL;
}

char *printer_get_name(printer_enum *pe, int i)
{
    if (!pe)
	return NULL;
    if (i < 0 || i >= pe->nprinters)
	return NULL;
    switch (pe->enum_level) {
      case 4:
	return pe->info.i4[i].pPrinterName;
      case 5:
	return pe->info.i5[i].pPrinterName;
      default:
	return NULL;
    }
}

void printer_finish_enum(printer_enum *pe)
{
    if (!pe)
	return;
    switch (pe->enum_level) {
      case 4:
	sfree(pe->info.i4);
	break;
      case 5:
	sfree(pe->info.i5);
	break;
    }
    sfree(pe);
}

printer_job *printer_start_job(char *printer)
{
    if (!strcmp(printer, PRINT_TO_CLIPBOARD_STRING)) {
	clipboard_init();
	return (printer_job *) PRINT_TO_CLIPBOARD_STRING;
    }
    printer_job *ret = snew(printer_job);
    DOC_INFO_1 docinfo;
    int jobstarted = 0, pagestarted = 0;

    ret->hprinter = NULL;
    if (!OpenPrinter(printer, &ret->hprinter, NULL))
	goto error;

    docinfo.pDocName = "PuTTY remote printer output";
    docinfo.pOutputFile = NULL;
    docinfo.pDatatype = "RAW";

    if (!StartDocPrinter(ret->hprinter, 1, (LPBYTE)&docinfo))
	goto error;
    jobstarted = 1;

    if (!StartPagePrinter(ret->hprinter))
	goto error;
    pagestarted = 1;

    return ret;

    error:
    if (pagestarted)
	EndPagePrinter(ret->hprinter);
    if (jobstarted)
	EndDocPrinter(ret->hprinter);
    if (ret->hprinter)
	ClosePrinter(ret->hprinter);
    sfree(ret);
    return NULL;
}

void printer_job_data(printer_job *pj, void *data, int len)
{
    DWORD written;

    if (!pj)
	return;

    if (pj == (printer_job *)PRINT_TO_CLIPBOARD_STRING) {
	clipboard_data(data, len);
	return;
    }

    WritePrinter(pj->hprinter, data, len, &written);
}

void printer_finish_job(printer_job *pj)
{
    if (!pj)
	return;

    if (pj == (printer_job *)PRINT_TO_CLIPBOARD_STRING) {
	clipboard_copy();
	return;
    }

    EndPagePrinter(pj->hprinter);
    EndDocPrinter(pj->hprinter);
    ClosePrinter(pj->hprinter);
    sfree(pj);
}

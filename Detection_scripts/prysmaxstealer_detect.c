/*
 * detect.c — Prysmax stealer detector
 * ===================================
 *
 * Detects the Prysmax infostealer family (Rust x86-64, tokio + WebSocket C2,
 * ZIP exfil via HTTP multipart) by static file signatures, known-sample
 * SHA-256 hashes and — on Windows — live system artifacts.
 *
 * NOTE: the analyzed sample is named 'rustystealer.exe' but is a Prysmax
 * build (developer build path /root/Prysmax/rust_current_build/). It is a
 * different family from the grabber_rs "rusty stealer" source tree in the
 * sibling rustystealer/ directory.
 *
 * IOCs were extracted by reverse engineering sample
 *   0ca17b7100de84cfa15ef901b4f5e6c910ca77ce478c98d3f4604f858f954285
 * See reconstructed/README.md in this directory for the full analysis.
 *
 * Build:
 *   Windows (MinGW):  x86_64-w64-mingw32-gcc -O2 -o detect.exe detect.c
 *   Windows (MSVC):   cl /O2 detect.c
 *   Linux/macOS:      gcc -O2 -o detect detect.c      (file scan only)
 *
 * Usage:
 *   detect <file> [file...]   scan file(s)
 *   detect <dir>              scan directory recursively
 *   detect --live             check live system artifacts (Windows only)
 *
 * Exit code: 0 = clean, 1 = suspicious, 2 = detected.
 *
 * Defensive security research use only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

/* ------------------------------------------------------------------ */
/* SHA-256 (compact public-domain-style implementation)               */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64], a, b, d, e, f, g, h, t1, t2, cc;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
    e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K256[i] + w[i];
        {
            uint32_t S0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
            uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
            t2 = S0 + maj;
        }
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c) {
    static const uint32_t H0[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(c->h, H0, sizeof H0);
    c->total = 0;
    c->buflen = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->total += len;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        len  -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    uint8_t pad = 0x80;
    uint8_t zero = 0x00;
    uint8_t lenbuf[8];
    int i;
    for (i = 0; i < 8; i++) lenbuf[7 - i] = (uint8_t)(bits >> (i * 8));
    sha256_update(c, &pad, 1);
    while (c->buflen != 56) sha256_update(c, &zero, 1);
    sha256_update(c, lenbuf, 8);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Boyer–Moore–Horspool substring search                              */
/* ------------------------------------------------------------------ */

static int find_bytes(const uint8_t *hay, size_t haylen,
                      const uint8_t *needle, size_t nlen) {
    size_t shift[256];
    size_t i, last;
    if (nlen == 0) return 1;
    if (haylen < nlen) return 0;
    for (i = 0; i < 256; i++) shift[i] = nlen;
    for (i = 0; i < nlen - 1; i++) shift[needle[i]] = nlen - 1 - i;
    last = nlen - 1;
    i = 0;
    while (i + nlen <= haylen) {
        if (hay[i + last] == needle[last] &&
            memcmp(hay + i, needle, nlen) == 0)
            return 1;
        i += shift[hay[i + last]];
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Prysmax IOCs                                                       */
/* ------------------------------------------------------------------ */

static const char *KNOWN_HASHES[] = {
    /* rustystealer.exe — Prysmax build (5.3 MB PE32+ x86-64) */
    "0ca17b7100de84cfa15ef901b4f5e6c910ca77ce478c98d3f4604f858f954285",
    NULL
};

typedef struct {
    const char    *name;
    const uint8_t *pat;
    size_t         plen;
    int            weight;
} sig_t;

#define SIGSTR(n, s, w) { n, (const uint8_t *)(s), sizeof(s) - 1, w }

static const sig_t SIGS[] = {
    /* --- family-unique markers --- */
    SIGSTR("developer build path /root/Prysmax/rust_current_build/",
           "/root/Prysmax/rust_current_build/", 3),
    SIGSTR("exfil archive name Prysmax.zip", "Prysmax.zip", 3),
    SIGSTR("apps module banner '=== Prysmax Apps Extraction Summary ==='",
           "=== Prysmax Apps Extraction Summary ===", 3),
    SIGSTR("social module log prefix '[PRYS SOCIAL att: law]'",
           "[PRYS SOCIAL att: law]", 3),

    /* --- state-machine / protocol strings --- */
    SIGSTR("ZIP state label COMPRESS_EMPTY_ZIP", "COMPRESS_EMPTY_ZIP", 2),
    SIGSTR("upload state label SEND_APPS_DATA", "SEND_APPS_DATA", 2),
    SIGSTR("C2 endpoint /api/upload", "/api/upload", 1),
    SIGSTR("C2 endpoint /api/social", "/api/social", 1),
    SIGSTR("Spanish exfil log 'Enviando datos al servidor'",
           "Enviando datos al servidor", 1),

    /* --- hardcoded developer/test artifacts --- */
    SIGSTR("hardcoded test RDP target 69.48.201.74", "69.48.201.74", 2),
    SIGSTR("hardcoded brute-force password 'R0gel!o2023'", "R0gel!o2023", 2),
    SIGSTR("hardcoded brute-force password 'Lawxsz2023!'", "Lawxsz2023!", 2),

    /* --- embedded third-party secrets --- */
    SIGSTR("Reddit OAuth client creds 'Basic b2hYcG9xclpZdWIxa2c6'",
           "Basic b2hYcG9xclpZdWIxa2c6", 2),
    SIGSTR("Instagram X-Mid token", "Ypg64wAAAAGXLOPZjFPNikpr8nJt", 2),
    SIGSTR("MetaMask extension id", "nkbihfbeogaeaoehlefnkodbefgpgknn", 1),
};

#define NUM_SIGS (sizeof(SIGS) / sizeof(SIGS[0]))

/* verdict thresholds */
#define SCORE_DETECT     4
#define SCORE_SUSPICIOUS 2

/* ------------------------------------------------------------------ */
/* File scanning                                                      */
/* ------------------------------------------------------------------ */

#define MAX_SCAN_SIZE (1024u * 1024u * 1024u)  /* 1 GiB cap */

static int g_worst = 0;  /* worst verdict across all scanned files */

static void hex_lower(const uint8_t *in, size_t n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) {
        out[i*2]   = hexd[in[i] >> 4];
        out[i*2+1] = hexd[in[i] & 15];
    }
    out[n*2] = '\0';
}

static void scan_file(const char *path) {
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    int score = 0;
    int hash_hit = 0;
    size_t i;

    if (!f) {
        printf("[ERR ] %s: cannot open\n", path);
        return;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (unsigned long)sz > MAX_SCAN_SIZE) {
        printf("[SKIP] %s: file too large\n", path);
        fclose(f);
        return;
    }
    buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) {
        printf("[ERR ] %s: out of memory\n", path);
        fclose(f);
        return;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        printf("[ERR ] %s: read failed\n", path);
        free(buf);
        fclose(f);
        return;
    }
    fclose(f);

    /* hash check */
    {
        sha256_ctx c;
        uint8_t digest[32];
        char hex[65];
        sha256_init(&c);
        sha256_update(&c, buf, (size_t)sz);
        sha256_final(&c, digest);
        hex_lower(digest, 32, hex);
        for (i = 0; KNOWN_HASHES[i]; i++) {
            if (strcmp(hex, KNOWN_HASHES[i]) == 0) {
                hash_hit = 1;
                break;
            }
        }
    }

    printf("[SCAN] %s (%ld bytes)\n", path, sz);

    if (hash_hit) {
        printf("       SHA-256 matches known Prysmax sample\n");
        score = 100;
    }

    for (i = 0; i < NUM_SIGS; i++) {
        if (find_bytes(buf, (size_t)sz, SIGS[i].pat, SIGS[i].plen)) {
            printf("       sig hit (+%d): %s\n", SIGS[i].weight, SIGS[i].name);
            score += SIGS[i].weight;
        }
    }

    if (score >= SCORE_DETECT) {
        printf("[DETECT] %s: Prysmax stealer (score %d)\n", path, score);
        if (g_worst < 2) g_worst = 2;
    } else if (score >= SCORE_SUSPICIOUS) {
        printf("[SUSP ] %s: possible Prysmax variant (score %d)\n", path, score);
        if (g_worst < 1) g_worst = 1;
    } else {
        printf("[CLEAN] %s (score %d)\n", path, score);
    }

    free(buf);
}

static int is_dir_path(const char *path) {
#ifdef _WIN32
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static void scan_path(const char *path);

static void scan_dir(const char *path) {
#ifdef _WIN32
    char pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    snprintf(pat, sizeof pat, "%s\\*", path);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        printf("[ERR ] %s: cannot list directory\n", path);
        return;
    }
    do {
        char full[MAX_PATH];
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        snprintf(full, sizeof full, "%s\\%s", path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            scan_dir(full);
        else
            scan_file(full);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    DIR *d = opendir(path);
    struct dirent *e;
    if (!d) {
        printf("[ERR ] %s: cannot list directory\n", path);
        return;
    }
    while ((e = readdir(d)) != NULL) {
        char full[4096];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(full, sizeof full, "%s/%s", path, e->d_name);
        if (is_dir_path(full))
            scan_dir(full);
        else
            scan_file(full);
    }
    closedir(d);
#endif
}

static void scan_path(const char *path) {
    if (is_dir_path(path))
        scan_dir(path);
    else
        scan_file(path);
}

/* ------------------------------------------------------------------ */
/* Live system checks (Windows only)                                  */
/* ------------------------------------------------------------------ */

static int live_checks(void) {
#ifdef _WIN32
    int score = 0;
    char path[MAX_PATH];
    const char *tmp;
    DWORD a;

    /* staging archive left in %TEMP% during/after exfiltration */
    tmp = getenv("TEMP");
    if (!tmp) tmp = getenv("TMP");
    if (tmp) {
        snprintf(path, sizeof path, "%s\\Prysmax.zip", tmp);
        a = GetFileAttributesA(path);
        if (a != INVALID_FILE_ATTRIBUTES) {
            printf("[LIVE ] staging archive found: %s (+4)\n", path);
            score += 4;
        } else {
            printf("[LIVE ] %s not present\n", path);
        }
    }

    printf("[LIVE ] note: also watch for outbound WebSocket /ws handshakes and "
           "multipart POSTs to /api/upload and /api/social\n");

    if (score >= SCORE_DETECT) { printf("[LIVE ] verdict: INFECTED (score %d)\n", score); return 2; }
    if (score >= SCORE_SUSPICIOUS) { printf("[LIVE ] verdict: SUSPICIOUS (score %d)\n", score); return 1; }
    printf("[LIVE ] verdict: no live indicators (score %d)\n", score);
    return 0;
#else
    printf("[LIVE ] live system checks are only available on Windows builds.\n");
    return 0;
#endif
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int i;

    if (argc < 2) {
        fprintf(stderr,
            "Prysmax stealer detector\n"
            "usage:\n"
            "  %s <file> [file...]  scan file(s)\n"
            "  %s <dir>             scan directory recursively\n"
            "  %s --live            live system checks (Windows)\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--live") == 0) {
            int r = live_checks();
            if (r > g_worst) g_worst = r;
        } else {
            scan_path(argv[i]);
        }
    }

    return g_worst;
}

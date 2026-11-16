/* LD_PRELOAD observation shim for the behaviour oracles (spec v2). Build: gcc -shared -fPIC -O1 imp_shim.c -o imp_shim.so -ldl
 * env IMP_LOG = log file, IMP_CANARY = the per-run token T. NEVER executes a command, never opens a path or sends a query that contains T: it logs and returns failure.
 * Log lines: KIND<TAB>text (newlines in text escaped). KIND in SYSTEM POPEN EXEC EXECSH OPEN STAT DIR SQL. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static int logfd = -2;
static const char *canary = NULL;

static void init(void) {
    if (logfd != -2) return;
    const char *p = getenv("IMP_LOG");
    canary = getenv("IMP_CANARY");
    logfd = p ? (int)syscall(SYS_openat, AT_FDCWD, p, O_WRONLY | O_APPEND | O_CREAT, 0666) : -1;
}

static void logl(const char *kind, const char *text) {
    init();
    if (logfd < 0) return;
    char buf[4096];
    size_t n = 0;
    for (const char *k = kind; *k && n < 16; k++) buf[n++] = *k;
    buf[n++] = '\t';
    for (const char *t = text ? text : "(null)"; *t && n < sizeof buf - 2; t++) {
        if (*t == '\n') { buf[n++] = '\\'; buf[n++] = 'n'; } else buf[n++] = *t;
    }
    buf[n++] = '\n';
    ssize_t r = write(logfd, buf, n); (void)r;
}

static int has_canary(const char *s) { init(); return canary && canary[0] && s && strstr(s, canary) != NULL; }

#define REAL(ret, name, args) static ret (*real_##name) args; \
    if (!real_##name) real_##name = dlsym(RTLD_NEXT, #name)

/* ---- command execution: logged, never run ---- */
int system(const char *cmd) { logl("SYSTEM", cmd); return 0; }

FILE *popen(const char *cmd, const char *mode) {
    logl("POPEN", cmd);
    REAL(FILE *, fopen, (const char *, const char *));
    return real_fopen("/dev/null", "r");
}

static void log_exec(const char *path, char *const argv[]) {
    char b[3000]; size_t n = 0;
    b[0] = 0;
    for (int i = 0; argv && argv[i] && i < 32 && n < sizeof b - 200; i++) n += snprintf(b + n, sizeof b - n, "%s%s", i ? " " : "", argv[i]);
    int sh = path && (strstr(path, "/sh") || strstr(path, "bash") || (argv && argv[0] && (strstr(argv[0], "sh"))));
    char line[3500];
    snprintf(line, sizeof line, "%s :: %s", path ? path : "(null)", b);
    logl(sh && argv && argv[1] && strcmp(argv[1], "-c") == 0 ? "EXECSH" : "EXEC", line);
}
int execve(const char *p, char *const a[], char *const e[]) { log_exec(p, a); errno = EACCES; return -1; }
int execv(const char *p, char *const a[]) { log_exec(p, a); errno = EACCES; return -1; }
int execvp(const char *p, char *const a[]) { log_exec(p, a); errno = EACCES; return -1; }
int execvpe(const char *p, char *const a[], char *const e[]) { log_exec(p, a); errno = EACCES; return -1; }
static int execl_common(const char *p, const char *a0, va_list ap) {
    char *argv[40]; int n = 0; argv[n++] = (char *)a0;
    while (n < 38) { char *x = va_arg(ap, char *); argv[n++] = x; if (!x) break; }
    argv[n < 40 ? n : 39] = NULL;
    log_exec(p, argv); errno = EACCES; return -1;
}
int execl(const char *p, const char *a0, ...) { va_list ap; va_start(ap, a0); int r = execl_common(p, a0, ap); va_end(ap); return r; }
int execlp(const char *p, const char *a0, ...) { va_list ap; va_start(ap, a0); int r = execl_common(p, a0, ap); va_end(ap); return r; }
int execle(const char *p, const char *a0, ...) { va_list ap; va_start(ap, a0); int r = execl_common(p, a0, ap); va_end(ap); return r; }

/* ---- filesystem paths: logged; paths containing the canary fail ---- */
int open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, mode);
}
int openat(int dfd, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); }
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return (int)syscall(SYS_openat, dfd, path, flags, mode);
}
FILE *fopen(const char *path, const char *mode) {
    REAL(FILE *, fopen, (const char *, const char *));
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return NULL; }
    return real_fopen(path, mode);
}
FILE *fopen64(const char *path, const char *mode) {
    REAL(FILE *, fopen64, (const char *, const char *));
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return NULL; }
    return real_fopen64(path, mode);
}
FILE *freopen(const char *path, const char *mode, FILE *s) {
    REAL(FILE *, freopen, (const char *, const char *, FILE *));
    logl("OPEN", path);
    if (has_canary(path)) { errno = ENOENT; return NULL; }
    return real_freopen(path, mode, s);
}
DIR *opendir(const char *path) {
    REAL(DIR *, opendir, (const char *));
    logl("DIR", path);
    if (has_canary(path)) { errno = ENOENT; return NULL; }
    return real_opendir(path);
}
int stat(const char *path, struct stat *st) {
    REAL(int, stat, (const char *, struct stat *));
    logl("STAT", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return real_stat(path, st);
}
int lstat(const char *path, struct stat *st) {
    REAL(int, lstat, (const char *, struct stat *));
    logl("STAT", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return real_lstat(path, st);
}
int access(const char *path, int m) {
    REAL(int, access, (const char *, int));
    logl("STAT", path);
    if (has_canary(path)) { errno = ENOENT; return -1; }
    return real_access(path, m);
}

/* ---- SQL: text logged, query never run (no database is needed) ---- */
int sqlite3_exec(void *db, const char *sql, void *cb, void *arg, char **err) { logl("SQL", sql); if (err) *err = NULL; return 0; }
int sqlite3_prepare_v2(void *db, const char *sql, int n, void **stmt, const char **tail) { logl("SQL", sql); if (stmt) *stmt = NULL; if (tail) *tail = NULL; return 0; }
int sqlite3_prepare_v3(void *db, const char *sql, int n, unsigned f, void **stmt, const char **tail) { logl("SQL", sql); if (stmt) *stmt = NULL; if (tail) *tail = NULL; return 0; }
int sqlite3_prepare(void *db, const char *sql, int n, void **stmt, const char **tail) { logl("SQL", sql); if (stmt) *stmt = NULL; if (tail) *tail = NULL; return 0; }
int mysql_query(void *m, const char *q) { logl("SQL", q); return 0; }
int mysql_real_query(void *m, const char *q, unsigned long len) { logl("SQL", q); return 0; }
int mysql_stmt_prepare(void *s, const char *q, unsigned long len) { logl("SQL", q); return 0; }
void *mysql_real_connect(void *m, const char *h, const char *u, const char *p, const char *d, unsigned port, const char *sock, unsigned long fl) { return m; }

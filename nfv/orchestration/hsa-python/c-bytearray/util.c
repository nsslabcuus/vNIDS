#ifndef _UTIL_H_
#define _UTIL_H_

#include <err.h>
#include <stdlib.h>
#include <string.h>

#define ARR_LEN(A) ( sizeof (A) / sizeof *(A) )

/* Equivalent to assert, but used for developer errors (incorrect assumptions)
   rather than user errors (incorrect usage). */
#define DEBUG assert

/* Memory allocation with error checking. */
#define xmalloc(SZ) xmalloc_ (SZ, __FILE__, __LINE__, __func__)
#define xrealloc(P, SZ) xrealloc_ (P, SZ, __FILE__, __LINE__, __func__)
#define xmemdup(P, SZ) xmemdup_ (P, SZ, __FILE__, __LINE__, __func__)
#define xstrdup(S) xstrdup_ (S, __FILE__, __LINE__, __func__)

static inline int
int_cmp (const void *a, const void *b)
{ return *(int *)a - *(int *)b; }

static inline void *
xmalloc_ (size_t size, const char *file, int line, const char *func)
{
  void *p = malloc (size);
  if (!p) err (1, "%s:%d (%s): malloc() failed", file, line, func);
  return p;
}

static inline void *
xrealloc_ (void *p, size_t size, const char *file, int line, const char *func)
{
  p = realloc (p, size);
  if (!p) err (1, "%s:%d (%s): realloc() failed", file, line, func);
  return p;
}

static inline void *
xmemdup_ (const void *src, size_t size, const char *file, int line, const char *func)
{
  void *p = xmalloc_ (size, file, line, func);
  memcpy (p, src, size);
  return p;
}

static inline char *
xstrdup_ (const char *s, const char *file, int line, const char *func)
{
  char *p = strdup (s);
  if (!p) err (1, "%s:%d (%s): strdup() failed", file, line, func);
  return p;
}

#endif

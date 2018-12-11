#include <Python.h>
#include "array.h"
#include <assert.h>
#include <stdio.h>
#include <math.h>
#include <err.h>
#include "util.c"


static bool
has_x (array_t x)
{
  return x & (x >> 1) & ODD_MASK;
}

static bool
has_z (array_t x)
{
  return has_x (~x);
}

static bool
reg_has_z (reg_t x)
{
  return ~x & (~x >> 1) & ODD_MASK;
}

/* Convert X from two-bit representation to integer.
 * X must contain only 0s and 1s (no x or z).
 */
static int
int_str (array_t a, char *out)
{
  char *s = out;
  for (int i = sizeof (array_t) / sizeof (uint16_t) - 1; i >= 0; i--) {
    int len;
    uint16_t x = a >> (i * 16);
    x = (x >> 1) & 0x5555;
    x = (x | (x >> 1)) & 0x3333;
    x = (x | (x >> 2)) & 0x0f0f;
    x = (x | (x >> 4)) & 0x00ff;
    len = sprintf (s, "D%d,", x);
    s += len;
  }
  return (int)(s - out);
}


array_t *
array_create (int len, enum bit_val val)
{
  array_t *res = PyMem_Malloc ( (size_t)ALLOC_WORDS(len) * sizeof (reg_t));
  memset (res, val * 0x55, (size_t)len * sizeof (array_t));
  memset (res + len, 0xff,
          (size_t)(ALLOC_WORDS(len) * sizeof (reg_t) - len * sizeof (array_t)));
  return res;
}

array_t *
array_copy(array_t *a, int len)
{
  int size = (int)(ALLOC_WORDS(len) * sizeof (reg_t));
  reg_t *res = PyMem_Malloc (size);
  return (array_t*)memcpy(res,a,size);
}

array_t *
array_from_str (const char *s)
{
  bool commas = strchr (s, ',');

  int div = commas ? ARRAY_BITS + 1 : ARRAY_BITS;
  int len = (int)strlen (s) + (commas ? 1 : 0);
  assert (len % div == 0);
  len /= div;

  const char *cur = s;
  array_t *res = array_create(len,BIT_0);
  for (int i = 0; i < len; i++) {
    array_t tmp = 0;
    for (int j = 0; j < ARRAY_BITS; j++) {
      enum bit_val val;
      switch (*cur) {
        case 'z': case 'Z': val = BIT_Z; break;
        case '0': val = BIT_0; break;
        case '1': val = BIT_1; break;
        case 'x': case 'X': val = BIT_X; break;
        default: errx (1, "Invalid character '%c' in \"%s\".", *cur, s);
      }
      tmp <<= 2;
      tmp |= val;
      cur++;
    }
    res[i] = tmp;
    if (commas) {
      assert (!*cur || *cur == ',');
      cur++;
    }
  }
  return res;
}

array_t *
array_from_int(uint64_t a, int len) {
  array_t *res = array_create (len, BIT_0);
  uint64_t cur = a;
  for (int i = 0; i < len; i++) {
    array_t tmp = 0;
    for (int j = 0; j < ARRAY_BITS; j++) {
      array_t val;
      switch (cur & 0x1) {
        case 0: val = (0x1 << (sizeof(val) * ARRAY_BITS - 2)); break;
        case 1: val = (0x2 << (sizeof(val) * ARRAY_BITS - 2)); break;
      }
      tmp >>= 2;
      tmp |= val;
      cur >>= 1;
    }
    res[len-i-1] = tmp;
  }
  return res;
}

bool
array_has_x (const array_t *a, int len)
{
  for (int i = 0; i < len; i++)
    if (has_x (a[i])) return true;
  return false;
}

bool
array_has_z (const array_t *a, int len)
{
  for (int i = 0; i < len; i++)
    if (has_z (a[i])) return true;
  return false;
}

char *
array_to_str (const array_t *a, int len, bool fmt_int)
{
  if (!a) return NULL;

  char buf[len * (ARRAY_BITS + 1)];
  char *cur = buf;
  for (int i = 0; i < len; i++) {
    array_t tmp = a[i];

    if (fmt_int && !has_x (tmp) && !has_z (tmp)) {
      cur += int_str (tmp, cur);
      continue;
    }

    char *next = cur + ARRAY_BITS - 1;
    for (int j = 0; j < ARRAY_BITS; j++) {
      static char chars[] = "z01x";
      *next-- = chars[tmp & BIT_X];
      tmp >>= 2;
    }
    cur += ARRAY_BITS;
    *cur++ = ',';
  }
  cur[-1] = 0;
  return xstrdup (buf);
}

array_t *
array_and (const array_t *a, const array_t *b, int len)
{
  reg_t *res = (reg_t *)array_create(len,BIT_0);
  reg_t *_a = (reg_t *)a;
  reg_t *_b = (reg_t *)b;
  for (int i = 0; i < ALLOC_WORDS(len); i++) {
    DEBUG (!reg_has_z (_a[i]) && !reg_has_z (_b[i]));
    res[i] = ((_a[i] | _b[i]) & ODD_MASK) | (_a[i] & _b[i] & EVEN_MASK);
  }
  return (array_t *)res;
}

array_t *
array_or (const array_t *a, const array_t *b, int len)
{
  reg_t *res = (reg_t *)array_create(len,BIT_0);
  reg_t *_a = (reg_t *)a;
  reg_t *_b = (reg_t *)b;
  for (int i = 0; i < ALLOC_WORDS(len); i++) {
      DEBUG (!reg_has_z (_a[i]) && !reg_has_z (_b[i]));
    res[i] = (_a[i] & _b[i] & ODD_MASK) | ((_a[i] | _b[i]) & EVEN_MASK);
  }
  return (array_t *)res;
}

array_t *
array_not (const array_t *a, int len)
{
  reg_t *res = (reg_t *)array_create(len,BIT_0);
  reg_t *_a = (reg_t *)a;
  for (int i = 0; i < ALLOC_WORDS(len); i++) {
    DEBUG (!reg_has_z (_a[i]));
    res[i] = ((_a[i] >> 1) & ODD_MASK) | ((_a[i] << 1) & EVEN_MASK);
  }
  return (array_t *)res;
}

array_t *
array_isect (const array_t *a, const array_t *b, int len)
{
  reg_t *res = (reg_t *)array_create(len,BIT_0);
  reg_t *_a = (reg_t *)a;
  reg_t *_b = (reg_t *)b;
  for (int i = 0; i < ALLOC_WORDS(len); i++) {
    res[i] = _a[i] & _b[i];
    if (reg_has_z (res[i])) {
        free(res);
        return NULL;
    }
  }
  return (array_t *)res;
}

bool
a_array_cmpl (const array_t *a, int len, int *n, array_t **res)
{
  *n = 0;
  for (int i = 0; i < len; i++) {
    DEBUG (!has_z (a[i]));
    array_t cur = ~a[i];
    while (cur) {
      DEBUG (*n < len * ARRAY_BITS);
      array_t next = cur & (cur - 1);
      array_t bit = cur & ~next;

      DEBUG ((bit & (bit - 1)) == 0);
      bit = ((bit >> 1) & ODD_MASK) | ((bit << 1) & EVEN_MASK);
      res[*n] = array_create (len, BIT_X);
      res[*n][i] &= ~bit;
      ++*n;
      cur = next;
    }
  }

  return *n;
}

bool
a_array_diff (const array_t *a, const array_t *b, int len, int *n, array_t **res)
{
  int n_cmpl;
  if (!a_array_cmpl (b, len, &n_cmpl, res)) return false;

  *n = 0;
  for (int i = 0; i < n_cmpl; i++) {
      res[*n] = array_isect (a, res[i], len);
      if (res[*n]) (*n)++;
  }
  for (int i = *n; i < n_cmpl; i++)
    free (res[i]);
  return *n;
}

array_t **
array_cmpl (const array_t *a, int len, int *n)
{
  array_t *tmp[len * ARRAY_BITS];
  if (!a_array_cmpl (a, len, n, tmp)) return NULL;
  array_t **res = PyMem_Malloc (*n * sizeof *res);
  memcpy(res,tmp,*n * sizeof *res);
  return res;
}

array_t **
array_diff (const array_t *a, const array_t *b, int len, int *n)
{
  array_t *tmp[len * ARRAY_BITS];
  if (!a_array_diff (a, b, len, n, tmp)) return NULL;
  array_t **res = PyMem_Malloc (*n * sizeof *res);
  memcpy(res,tmp,*n * sizeof *res);
  return res;
}

array_t *
array_rw (const array_t *a,const array_t *mask, const array_t *rw, int len, int *card)
{
  *card = (EXTRA_BYTES(len)) * -8;
  reg_t *res = (reg_t *)array_create(len,BIT_0);
  reg_t *_a = (reg_t *)a;
  reg_t *_mask = (reg_t *)mask;
  reg_t *_rw = (reg_t *)rw;
  for (int i = 0; i < ALLOC_WORDS(len); i++) {
    reg_t tmp = _a[i] & (_a[i] >> 1) & _mask[i] & ODD_MASK;
    *card += __builtin_popcountll (tmp);
    res[i] = (((_a[i] | _mask[i]) & _rw[i]) & ODD_MASK) |
           (((_a[i] & _mask[i]) | _rw[i]) & EVEN_MASK);
  }

  return (array_t *)res;
}

bool
array_is_sub (const array_t *a, const array_t *b, int len)
{
  reg_t *_a = (reg_t *)a;
  reg_t *_b = (reg_t *)b;
  for (int i = 0; i < ALLOC_WORDS(len); i++)
    if (_a[i] & ~_b[i]) return false;
  return true;
}

bool
array_is_equal (const array_t *a, const array_t *b, int len)
{
  reg_t *_a = (reg_t *)a;
  reg_t *_b = (reg_t *)b;
  for (int i = 0; i < ALLOC_WORDS(len); i++)
    if (_b[i] != _a[i]) return false;
  return true;
}

void
array_set_byte(array_t *a, array_t new_byte, int byte_pos, int len)
{
  a[len - byte_pos - 1] = new_byte;
}

void
array_set_bit(array_t *a, array_t new_bit, int byte_pos, int bit_pos, int len)
{
  a[len - byte_pos - 1] = (a[len - byte_pos - 1] & ~(0x0003 << (2 * bit_pos))) |
      ((new_bit & 0x0003) << (2 * bit_pos));
}

array_t
array_get_byte(const array_t *a, int byte_pos, int len)
{
  return a[len - byte_pos - 1];
}

array_t
array_get_bit(const array_t *a, int byte_pos, int bit_pos, int len)
{
  array_t r = a[len - byte_pos - 1];
  return (r >> (2 * bit_pos)) & 0x0003;
}


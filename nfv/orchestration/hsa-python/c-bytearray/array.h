#ifndef _ARRAY_H_
#define _ARRAY_H_

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

typedef uint16_t array_t;

#if __x86_64 || __amd64 || _M_X64
typedef uint64_t reg_t;
#else
typedef uint32_t reg_t;
#endif

enum bit_val { BIT_Z = 0, BIT_0, BIT_1, BIT_X };

#define ARRAY_BITS (int)(sizeof (array_t) * CHAR_BIT / 2)
#define REG_WIDTH (int)(sizeof (reg_t) / sizeof (array_t))

/* If using anything larger than 64-bit, these need to be changed. */
#define EVEN_MASK ( (reg_t) 0xaaaaaaaaaaaaaaaaull )
#define ODD_MASK  ( (reg_t) 0x5555555555555555ull )
#define ALLOC_WORDS(len) ceil((double)len / REG_WIDTH)
#define EXTRA_BYTES(len) (int)(ALLOC_WORDS(len) * REG_WIDTH) - len

array_t *array_create   (int, enum bit_val);
array_t *array_copy     (array_t *, int);
array_t *array_from_str (const char *);
array_t *array_from_int (uint64_t, int);
bool     array_has_x    (const array_t *, int);
bool     array_has_z    (const array_t *, int);
char    *array_to_str   (const array_t *, int, bool);

array_t *array_and    (const array_t *, const array_t *, int);
array_t *array_or     (const array_t *, const array_t *, int);
array_t *array_not    (const array_t *, int);

array_t *array_isect  (const array_t *, const array_t *, int);
array_t **array_cmpl  (const array_t *, int, int *);
array_t **array_diff  (const array_t *, const array_t *, int, int *);

array_t *array_rw     (const array_t *,const array_t *, const array_t*, int, int*);

bool     array_is_sub   (const array_t *, const array_t *, int);
bool     array_is_equal (const array_t *, const array_t *, int);

void     array_set_byte   (array_t *, array_t, int, int);
void     array_set_bit    (array_t *, array_t, int, int, int);
array_t  array_get_byte   (const array_t *, int, int);
array_t  array_get_bit    (const array_t *, int, int, int);

#endif


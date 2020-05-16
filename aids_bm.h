#ifndef AIDS_BM_H
#define AIDS_BM_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>

#ifndef ASIZE
#define ASIZE 256
#endif

struct aids_bm
{
	u8 *		pattern;
	unsigned int	patlen;
	unsigned int 	bad_shift[ASIZE];
	unsigned int	good_shift[0];
};

struct aids_bm *aids_bm_init(const char *pattern, u32 len, u8 ignore_case);
void aids_bm_deinit(struct aids_bm *bm);
u32 aids_bm_find(struct aids_bm *bm, const u8 *text, u32 text_len, u8 ignore_case);

#define AIDS_BM_NOTFIND(x) ((x) == UINT_MAX)

#endif

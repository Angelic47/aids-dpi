#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include "aids_bm.h"

u32 aids_bm_find(struct aids_bm *bm, const u8 *text, u32 text_len, u8 ignore_case)
{
	u32 i;
	int shift = bm->patlen - 1, bs;

	while (shift < text_len) {
		for (i = 0; i < bm->patlen; i++) 
			if ((ignore_case ? toupper(text[shift-i])
				: text[shift-i])
				!= bm->pattern[bm->patlen-1-i])
				 goto next;
				 
		return shift-(bm->patlen-1);

next:	bs = bm->bad_shift[text[shift-i]];

		shift = max_t(int, shift-i+bs, shift+bm->good_shift[i]);
	}

	return UINT_MAX;
}

static int aids_subpattern(u8 *pattern, int i, int j, int g)
{
	int x = i+g-1, y = j+g-1, ret = 0;

	while(pattern[x--] == pattern[y--]) {
		if (y < 0) {
			ret = 1;
			break;
		}
		if (--g == 0) {
			ret = pattern[i-1] != pattern[j-1];
			break;
		}
	}

	return ret;
}

static void aids_compute_prefix_tbl(struct aids_bm *bm, u8 ignore_case)
{
	int i, j, g;

	for (i = 0; i < ASIZE; i++)
		bm->bad_shift[i] = bm->patlen;
	for (i = 0; i < bm->patlen - 1; i++) {
		bm->bad_shift[bm->pattern[i]] = bm->patlen - 1 - i;
		if (ignore_case)
			bm->bad_shift[tolower(bm->pattern[i])]
			    = bm->patlen - 1 - i;
	}

	bm->good_shift[0] = 1;
	for (i = 1; i < bm->patlen; i++)
		bm->good_shift[i] = bm->patlen;
        for (i = bm->patlen-1, g = 1; i > 0; g++, i--) {
		for (j = i-1; j >= 1-g ; j--)
			if (aids_subpattern(bm->pattern, i, j, g)) {
				bm->good_shift[g] = bm->patlen-j-g;
				break;
			}
	}
}

struct aids_bm *aids_bm_init(const char *pattern, u32 len, u8 ignore_case)
{
	struct aids_bm *bm;
	u32 i;
	u32 prefix_tbl_len = len * sizeof(unsigned int);
	size_t priv_size = sizeof(*bm) + len + prefix_tbl_len;

	bm = (struct aids_bm *)kmalloc(priv_size, GFP_KERNEL);
	if (!bm)
	{
		pr_warning("[AngelIDS][DPI] aids_bm_init alloc mem failed, priv_size: %d, pattern: [%s], pattlen: %d\n", priv_size, pattern, len);
		return NULL;
	}

	bm->patlen = len;
	bm->pattern = (u8 *) bm->good_shift + prefix_tbl_len;
	if (ignore_case)
		for (i = 0; i < len; i++)
			bm->pattern[i] = toupper(((u8 *)pattern)[i]);
	else
		memcpy(bm->pattern, pattern, len);
	aids_compute_prefix_tbl(bm, ignore_case);

	return bm;
}

void aids_bm_deinit(struct aids_bm *bm)
{
	kfree(bm);
}

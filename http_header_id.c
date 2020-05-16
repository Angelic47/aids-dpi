#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include "http_header_id.h"
#include "tire.h"

TrieSTPtr g_aids_httpheader_tire = NULL;

int aids_httpheader_id_init(void)
{
	g_aids_httpheader_tire = aids_CreateTrie();
	if(!g_aids_httpheader_tire)
	{
		pr_warning("[AngelIDS][DPI] aids_httpheader_id_init failed to alloc tire root");
		return -ENOMEM;
	}
	
	AIDS_HTTPHEADER_INSERT_TIRE(g_aids_httpheader_tire);
	
	return 0;
}

void aids_httpheader_id_deinit(void)
{
	aids_DeleteTrie(g_aids_httpheader_tire);
}

int aids_httpheader_lookup_seq(char *headername, unsigned int headerlen)
{
	int result = AIDS_Priv_INTERNAL_ONLY;
	if(headerlen < 20)
	{
		result = aids_SearchTrie(g_aids_httpheader_tire, headername, headerlen);
		if(result == AIDS_TIRE_NO_MATCH)
			result = AIDS_Priv_INTERNAL_ONLY;
	}
	return result;
}

int aids_httpheader_lookup(char *headername, unsigned int headerlen)
{
	return aids_SearchTrie(g_aids_httpheader_tire, headername, headerlen);
}
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include "tire.h"

TrieNodePtr aids_CreateTrieNode(char key)
{
    TrieNodePtr t = (TrieNodePtr)kmalloc(sizeof(TrieNode), GFP_KERNEL);
	if(!t)
	{
		pr_warning("[AngelIDS][DPI] aids_CreateTrieNode: kmalloc failed!\n");
		return NULL;
	}
    memset(t, 0, sizeof(TrieNode));
    t->value = key;
    return t;
}

TrieSTPtr aids_CreateTrie(void)
{
    TrieSTPtr t = (TrieSTPtr)kmalloc(sizeof(TrieNode), GFP_KERNEL);
	if(!t)
	{
		pr_warning("[AngelIDS][DPI] aids_CreateTrie: kmalloc failed!\n");
		return NULL;
	}
    memset(t, 0, sizeof(TrieNode));
    return t;
}

void aids_InsertTire(TrieSTPtr root, char *key, int matchValue)
{
    int i = 0;
    TrieSTPtr tmp = root;
    while (*(key + i) != '\0') {
        if (tmp->next[toupper(*(key + i))] == NULL) {
            TrieNodePtr t = aids_CreateTrieNode(toupper(*(key + i)));
			if(!t)
				return;
            tmp->next[toupper(*(key + i))] = t;
            tmp->count++;
        }
        tmp = tmp->next[toupper(*(key + i))];
        i++;
    }
    tmp->isEndOfWord = 1;
	tmp->matchValue = matchValue;
}

void aids_DeleteTrie(TrieSTPtr t)
{
	int i;
    for (i = 0; i < AIDS_TIRE_CHARLENGTH; i++) {
        if (t->next[i] != NULL) {
            aids_DeleteTrie(t->next[i]);
            kfree(t->next[i]);
            t->next[i] = NULL;
        }
    }
}

int aids_SearchTrie(TrieSTPtr root, char *str, unsigned int length)
{
    if (root == NULL)
        return 0;
    TrieSTPtr tmp = root;
    int i = 0;
    while (i < length && str[i] != NULL){
        if (tmp->next[toupper(str[i])] != NULL){
            tmp = tmp->next[toupper(str[i])];
        }
        else
            return AIDS_TIRE_NO_MATCH;
        i++;
    }
    if (tmp->isEndOfWord) {
        return tmp->matchValue;
    }
    else {
        return AIDS_TIRE_NO_MATCH;
    }
}

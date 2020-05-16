#ifndef __AIDS_TIRE_H__
#define __AIDS_TIRE_H__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#define AIDS_TIRE_CHARLENGTH 256
#define AIDS_TIRE_NO_MATCH -1

struct _TrieNode {
    struct _TrieNode *next[AIDS_TIRE_CHARLENGTH];
    int isEndOfWord;
    int count;
    char value;
	int matchValue;
};
typedef struct _TrieNode TrieNode;
typedef struct _TrieNode* TrieNodePtr;
#define TrieSTPtr TrieNodePtr

TrieNodePtr aids_CreateTrieNode(char key);

TrieSTPtr aids_CreateTrie(void);

void aids_InsertTire(TrieSTPtr root, char *key, int matchValue);

void aids_DeleteTrie(TrieSTPtr t);

int aids_SearchTrie(TrieSTPtr root, char *str, unsigned int length);

#endif

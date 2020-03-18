#pragma once

#include "pin.H"

typedef struct itreenode {
	ADDRINT start_addr, end_addr;   // range [a, b]
	void *data;						// user-supplied data
	struct itreenode *left, *right;	// left and right children
} itreenode_t;

itreenode_t *itree_init(ADDRINT start_addr, ADDRINT end_addr, void* data);
bool itree_insert(itreenode_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data);
itreenode_t* itree_delete(itreenode_t* tree, ADDRINT start_addr, ADDRINT end_addr);
itreenode_t *itree_search(itreenode_t *tree, ADDRINT val);
BOOL itree_dealloc(itreenode_t* tree);
bool itree_verify(itreenode_t *tree);


void itree_print(itreenode_t *node, ADDRINT lvl);
VOID itree_stats(itreenode_t *node);
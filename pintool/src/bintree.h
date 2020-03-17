#pragma once

#include "pin.H"

// Node struct
typedef struct node {
	ADDRINT start_addr, end_addr;   // range [a, b]
	void *data;						// user-supplied data
	struct node *gt, *lt;			// left and right children
} node_t;

node_t *bintree_init(ADDRINT start_addr, ADDRINT end_addr, void* data);
bool bintree_insert(node_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data);
node_t* bintree_delete(node_t* tree, ADDRINT start_addr, ADDRINT end_addr);
node_t *bintree_search(node_t *tree, ADDRINT val);
BOOL bintree_dealloc(node_t* tree);
bool bintree_verify(node_t *tree);


void bintree_print(node_t *node, UINT64 lvl);
VOID bintree_stats(node_t *node);
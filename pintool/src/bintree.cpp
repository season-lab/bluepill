#include "bintree.h"
#include <iostream>

// borrowed and adapted from https://github.com/Frky/iCi

// Init tree
node_t *bintree_init(ADDRINT start_addr, ADDRINT end_addr, void *data) {
	node_t *tree = (node_t *)malloc(sizeof(node_t));
	tree->start_addr = start_addr;
	tree->end_addr = end_addr;
	tree->data = data;
	tree->lt = NULL;
	tree->gt = NULL;
	return tree;
}

// Insert element in tree
bool bintree_insert(node_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data) {

	node_t *senti = tree;

	// Insert duplicate
	if (senti->start_addr == start_addr && senti->end_addr == end_addr)
		return false;
	// Insert in right subtree
	else if (senti->end_addr < start_addr) {
		// Right subtree present
		if (senti->gt) {
			return bintree_insert(senti->gt, start_addr, end_addr, data);
		}
		// No right subtree
		else {
			senti->gt = bintree_init(start_addr, end_addr, data);
			return true;
		}
	}
	// Insert in left subtree
	else {
		// Left subtree present
		if (senti->lt) {
			return bintree_insert(senti->lt, start_addr, end_addr, data);
		}
		// No left subtree
		else {
			senti->lt = bintree_init(start_addr, end_addr, data);
			return true;
		}
	}
	return false;
}

// DCD added node removal for BST
node_t* bintree_delete(node_t* tree, ADDRINT start_addr, ADDRINT end_addr) {
	// base case
	if (tree == NULL) return NULL;

	// node found
	if (tree->start_addr == start_addr && tree->end_addr == end_addr) {
		node_t* tmp;
		// node with only one child
		if (tree->lt == NULL) { // or no child
			tmp = tree->gt;
			free(tree);
			return tmp;
		}
		else if (tree->gt == NULL) {
			tmp = tree->lt;
			free(tree);
			return tmp;
		}
		else {
			// node with two children: find leftmost descendant in right
			// subtree and paste it into current node, then remove it
			tmp = tree->gt;
			while (tmp && tmp->lt) tmp = tmp->lt;
			tree->start_addr = tmp->start_addr;
			tree->end_addr = tmp->end_addr;
			tree->data = tmp->data; // TODO memory leak here
			tree->gt = bintree_delete(tree->gt, tmp->start_addr, tmp->end_addr);
		}
	}
	else if (tree->end_addr < start_addr) { // right subtree
		tree->gt = bintree_delete(tree->gt, start_addr, end_addr);
	}
	else { // left subtree
		tree->lt = bintree_delete(tree->lt, start_addr, end_addr);
	}
	return tree;
}

// Search inside binary tree
node_t *bintree_search(node_t *tree, ADDRINT val) {
	if (!tree)
		return NULL;
	node_t *senti = tree;

	// Address found in interval
	if (val >= senti->start_addr && val <= senti->end_addr) {
		return senti;
	}
	// Search right subtree
	else if (senti->end_addr < val)
		if (senti->gt)
			return bintree_search(senti->gt, val);
		else
			return NULL;
	// Search left subtree
	else
		if (senti->lt)
			return bintree_search(senti->lt, val);
		else
			return NULL;
	return NULL;
}

// DCD added to perform sanity check
bool bintree_verify(node_t *tree) {
	if (!tree) return true;

	// well-formed interval: redundant, unless Pin screws up (why so?)
	if (tree->end_addr <= tree->start_addr) return false;

	// left child contains interval ending beyond the parent interval's start
	if (tree->lt && tree->lt->end_addr >= tree->start_addr) return false;

	// right child contains interval starting before the parent interval's end
	if (tree->gt && tree->gt->start_addr <= tree->end_addr) return false;

	return (bintree_verify(tree->lt) && bintree_verify(tree->gt));
}


void bintree_print(node_t *node, UINT64 lvl) {
	if (!node)
		return;

	fprintf(stderr, "Level: %lld , Range: [0x%0x, 0x%0x]\n",
		lvl, node->start_addr, node->end_addr);
	bintree_print(node->lt, lvl + 1);
	bintree_print(node->gt, lvl + 1);

	return;
}

UINT32 depth(node_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + MAX(depth(tree->gt), depth(tree->lt));
}

UINT32 nb_nodes(node_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + nb_nodes(tree->gt) + nb_nodes(tree->lt);
}

// TODO compute balance factor
VOID bintree_stats(node_t *node) {
	std::cerr << "NODES: " << nb_nodes(node) << std::endl;
	std::cerr << "DEPTH: " << depth(node) << std::endl;
	return;
}

// Deallocate tree
BOOL bintree_dealloc(node_t* tree) {
	if (!tree)
		return true;

	node_t *senti = tree;
	node_t *gt = tree->gt;
	node_t *lt = tree->lt;
	free(tree); // TODO memory leak on data

	if (gt) {
		bintree_dealloc(gt);
	}
	if (lt) {
		bintree_dealloc(lt);
	}

	return true;
}
#include "itree.h"
#include <iostream>

// most of the following code is a reworked and extended
// version of https://github.com/Frky/iCi (ACSAC'18)

// Init interval tree
itreenode_t *itree_init(ADDRINT start_addr, ADDRINT end_addr, void *data) {
	itreenode_t *tree = (itreenode_t *)malloc(sizeof(itreenode_t));
	tree->start_addr = start_addr;
	tree->end_addr = end_addr;
	tree->data = data;
	tree->left = NULL;
	tree->right = NULL;
	return tree;
}

// Insert element in interval tree
bool itree_insert(itreenode_t *tree, ADDRINT start_addr, ADDRINT end_addr, void* data) {

	itreenode_t *senti = tree;

	// Insert duplicate
	if (senti->start_addr == start_addr && senti->end_addr == end_addr)
		return false;
	// Insert in right subtree
	else if (senti->end_addr < start_addr) {
		// Right subtree present
		if (senti->right) {
			return itree_insert(senti->right, start_addr, end_addr, data);
		}
		// No right subtree
		else {
			senti->right = itree_init(start_addr, end_addr, data);
			return true;
		}
	}
	// Insert in left subtree
	else {
		// Left subtree present
		if (senti->left) {
			return itree_insert(senti->left, start_addr, end_addr, data);
		}
		// No left subtree
		else {
			senti->left = itree_init(start_addr, end_addr, data);
			return true;
		}
	}
	return false;
}

// DCD added node removal
itreenode_t* itree_delete(itreenode_t* tree, ADDRINT start_addr, ADDRINT end_addr) {
	// base case
	if (tree == NULL) return NULL;

	// node found
	if (tree->start_addr == start_addr && tree->end_addr == end_addr) {
		itreenode_t* tmp;
		// node with only one child
		if (tree->left == NULL) { // or no child
			tmp = tree->right;
			free(tree);
			return tmp;
		}
		else if (tree->right == NULL) {
			tmp = tree->left;
			free(tree);
			return tmp;
		}
		else {
			// node with two children: find leftmost descendant in right
			// subtree and paste it into current node, then remove it
			tmp = tree->right;
			while (tmp && tmp->left) tmp = tmp->left;
			tree->start_addr = tmp->start_addr;
			tree->end_addr = tmp->end_addr;
			tree->data = tmp->data; // TODO memory leak here
			tree->right = itree_delete(tree->right, tmp->start_addr, tmp->end_addr);
		}
	}
	else if (tree->end_addr < start_addr) { // right subtree
		tree->right = itree_delete(tree->right, start_addr, end_addr);
	}
	else { // left subtree
		tree->left = itree_delete(tree->left, start_addr, end_addr);
	}
	return tree;
}

// Search inside interval tree
itreenode_t *itree_search(itreenode_t *tree, ADDRINT val) {
	if (!tree)
		return NULL;
	itreenode_t *senti = tree;

	// Address found in interval
	if (val >= senti->start_addr && val <= senti->end_addr) {
		return senti;
	}
	// Search right subtree
	else if (senti->end_addr < val)
		if (senti->right)
			return itree_search(senti->right, val);
		else
			return NULL;
	// Search left subtree
	else
		if (senti->left)
			return itree_search(senti->left, val);
		else
			return NULL;
	return NULL;
}

// DCD added to perform sanity check
bool itree_verify(itreenode_t *tree) {
	if (!tree) return true;

	// well-formed interval: redundant, unless Pin screws up (why so?)
	if (tree->end_addr <= tree->start_addr) return false;

	// left child contains interval ending beyond the parent interval's start
	if (tree->left && tree->left->end_addr >= tree->start_addr) return false;

	// right child contains interval starting before the parent interval's end
	if (tree->right && tree->right->start_addr <= tree->end_addr) return false;

	return (itree_verify(tree->left) && itree_verify(tree->right));
}


void itree_print(itreenode_t *node, ADDRINT lvl) {
	if (!node)
		return;

	fprintf(stderr, "Level: %u , Range: [0x%0x, 0x%0x]\n",
		lvl, node->start_addr, node->end_addr);
	itree_print(node->left, lvl + 1);
	itree_print(node->right, lvl + 1);

	return;
}

UINT32 depth(itreenode_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + MAX(depth(tree->right), depth(tree->left));
}

UINT32 nb_nodes(itreenode_t *tree) {
	if (!tree)
		return 0;
	else
		return 1 + nb_nodes(tree->right) + nb_nodes(tree->left);
}

// TODO compute balance factor
VOID itree_stats(itreenode_t *node) {
	std::cerr << "NODES: " << nb_nodes(node) << std::endl;
	std::cerr << "DEPTH: " << depth(node) << std::endl;
	return;
}

// Deallocate interval tree
BOOL itree_dealloc(itreenode_t* tree) {
	if (!tree)
		return true;

	itreenode_t *senti = tree;
	itreenode_t *right = tree->right;
	itreenode_t *left = tree->left;
	free(tree); // TODO memory leak on data

	if (right) {
		itree_dealloc(right);
	}
	if (left) {
		itree_dealloc(left);
	}

	return true;
}
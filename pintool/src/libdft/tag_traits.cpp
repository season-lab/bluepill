#include <algorithm>
#include <set>
#include <bitset>
#include <string>
#include <sstream>
#include "tag_traits.h"

/* *** Unsigned char based tags. ************************************/
//extern void* __dso_handle; // needed when compiling with PinCRT

template<>
unsigned char tag_combine(unsigned char const & lhs, unsigned char const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(unsigned char & lhs, unsigned char const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(unsigned char const & tag) {
	std::stringstream ss;
	ss << std::bitset<(sizeof(tag) << 3)>(tag);
	return ss.str();
	//return std::bitset<(sizeof(tag) << 3)>(tag).to_string();
}

/* *** Workaround for initializer lists *****************************/
std::set<uint32_t> setValWrapper() {
	std::set<uint32_t> s;
	s.insert(1);
	return s;
}

std::set<fdoff_t> setFdoffWrapper() {
	std::set<fdoff_t> s;
	s.insert(fdoff_t(0,0));
	return s;
}


/* *** set<uint32_t> based tags. ************************************/
/* define the set/cleared values */
const std::set<uint32_t> tag_traits<std::set<uint32_t> >::cleared_val = std::set<uint32_t>();

const std::set<uint32_t> tag_traits<std::set<uint32_t> >::set_val = setValWrapper(); //std::set<uint32_t>{1};

template<>
std::set<uint32_t> tag_combine(std::set<uint32_t> const & lhs, std::set<uint32_t> const & rhs) {
	std::set<uint32_t> res;

	std::set_union(
			lhs.begin(), lhs.end(),
			rhs.begin(), rhs.end(),
			std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<uint32_t> & lhs, std::set<uint32_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<uint32_t> const & tag) {
	std::set<uint32_t>::const_iterator t;
	std::stringstream ss;

	ss << "{";
	if (!tag.empty()) {
		std::set<uint32_t>::const_iterator last = --tag.end(); //std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << *t << ", ";
		ss << *(t++);
	}
	ss << "}";
	return ss.str();
}


/* *** set<fdoff_t> based tags. ************************************/
/* 
   define the set/cleared values
   the set_val is kind of arbitrary here - represents offset 0 of stdin
 */
const std::set<fdoff_t> tag_traits<std::set<fdoff_t> >::cleared_val = std::set<fdoff_t>();
const std::set<fdoff_t> tag_traits<std::set<fdoff_t> >::set_val = setFdoffWrapper(); //std::set<fdoff_t>{fdoff_t{0, 0}};

template<>
std::set<fdoff_t> tag_combine(std::set<fdoff_t> const & lhs, std::set<fdoff_t> const & rhs) {
	std::set<fdoff_t> res;

	std::set_union(
		lhs.begin(), lhs.end(),
		rhs.begin(), rhs.end(),
		std::inserter(res, res.begin())
	);

	return res;
}

template<>
void tag_combine_inplace(std::set<fdoff_t> & lhs, std::set<fdoff_t> const & rhs) {
	lhs.insert(rhs.begin(), rhs.end());
}

template<>
std::string tag_sprint(std::set<fdoff_t> const & tag) {
	std::set<fdoff_t>::const_iterator t;
	std::stringstream ss;

	ss << "{";
	if (!tag.empty()) {
		std::set<fdoff_t>::const_iterator last = --tag.end(); //std::prev(tag.end());
		for (t = tag.begin(); t != last; t++)
			ss << (*t).first << ":" << (*t).second << ", ";
		ss << (*t).first << ":" << (*t).second;
		t++;
	}
	ss << "}";
	return ss.str();
}


/* *** bitset<> based tags. ****************************************/
/*
   define the set/cleared values
   the set_val is kind of arbitrary - represents all bits set
 */
const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE> >::cleared_val = std::bitset<TAG_BITSET_SIZE>(); //std::bitset<TAG_BITSET_SIZE>{};
const std::bitset<TAG_BITSET_SIZE> tag_traits<std::bitset<TAG_BITSET_SIZE> >::set_val = std::bitset<TAG_BITSET_SIZE>().set(); //std::bitset<TAG_BITSET_SIZE>{}.set();

template<>
std::bitset<TAG_BITSET_SIZE> tag_combine(std::bitset<TAG_BITSET_SIZE> const & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	return lhs | rhs;
}

template<>
void tag_combine_inplace(std::bitset<TAG_BITSET_SIZE> & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs) {
	lhs |= rhs;
}

template<>
std::string tag_sprint(std::bitset<TAG_BITSET_SIZE> const & tag) {
	std::stringstream ss;
	ss << tag;
	return ss.str();
	//return tag.to_string();
}

/* vim: set noet ts=4 sts=4 : */

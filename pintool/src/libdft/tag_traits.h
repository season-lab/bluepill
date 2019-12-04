#ifndef LIBDFT_TAG_TRAITS_H
#define LIBDFT_TAG_TRAITS_H

#include <set>
#include <bitset>
#include <string>

/********************************************************
 templates for tag type and combine functions
 ********************************************************/
template<typename T> struct tag_traits {};

/* combine tags */
template<typename T> T tag_combine(T const & lhs, T const & rhs);

/* combine tags in-place */
template<typename T> void tag_combine_inplace(T & lhs, T const & rhs);

/* print to string */
template<typename T> std::string tag_sprint(T const & tag);


/********************************************************
 uint8_t tags
 ********************************************************/
typedef uint8_t libdft_tag_uint8;

template<>
struct tag_traits<unsigned char>
{
	typedef unsigned char type;
	static const bool is_container = false;
	static const uint8_t cleared_val = 0;
	static const uint8_t set_val = 1;
};

template<>
unsigned char tag_combine(unsigned char const & lhs, unsigned char const & rhs);

template<>
void tag_combine_inplace(unsigned char & lhs, unsigned char const & rhs);

template<>
std::string tag_sprint(unsigned char const & tag);

/********************************************************
 uint32_t set tags
 ********************************************************/
typedef std::set<uint32_t> libdft_tag_set_uint32; // DCD typedef typename vs C++03

template<>
struct tag_traits<std::set<uint32_t> >
{
	typedef std::set<uint32_t> type; // DCD typedef typename vs C++03
	typedef uint32_t inner_type;
	static const bool is_container = true;
	static const std::set<uint32_t> cleared_val;
	static const std::set<uint32_t> set_val;
};

template<>
std::set<uint32_t> tag_combine(std::set<uint32_t> const & lhs, std::set<uint32_t> const & rhs);

template<>
void tag_combine_inplace(std::set<uint32_t> & lhs, std::set<uint32_t> const & rhs);

template<>
std::string tag_sprint(std::set<uint32_t> const & tag);

/********************************************************
 fd-offset set tags
 ********************************************************/
typedef std::pair<uint32_t,uint32_t> fdoff_t; // DCD typedef typename vs C++03
typedef std::set<fdoff_t> libdft_tag_set_fdoff; // DCD typedef typename vs C++03

template<>
struct tag_traits<std::set<fdoff_t> >
{
	typedef std::set<fdoff_t> type; // DCD typedef typename vs C++03
	typedef fdoff_t inner_type;
	static const bool is_container = true;
	static const std::set<fdoff_t> cleared_val;
	static const std::set<fdoff_t> set_val;
};

template<>
std::set<std::set<fdoff_t> > tag_combine(std::set<std::set<fdoff_t> > const & lhs, std::set<std::set<fdoff_t> > const & rhs);

template<>
void tag_combine_inplace(std::set<std::set<fdoff_t> > & lhs, std::set<std::set<fdoff_t> > const & rhs);

template<>
std::string tag_sprint(std::set<std::set<fdoff_t> > const & tag);

/********************************************************
 bitset tags
 ********************************************************/
#if TAG_BITSET_SIZE < 8
#undef TAG_BITSET_SIZE
#define TAG_BITSET_SIZE 8
#endif
typedef std::bitset<TAG_BITSET_SIZE> libdft_tag_bitset; // DCD typedef typename vs C++03

template<>
struct tag_traits<std::bitset<TAG_BITSET_SIZE> >
{
	typedef std::bitset<TAG_BITSET_SIZE> type; // DCD typedef typename vs C++03
	typedef uint8_t inner_type; // ???
	static const bool is_container = false;
	static const std::bitset<TAG_BITSET_SIZE> cleared_val;
	static const std::bitset<TAG_BITSET_SIZE> set_val;
};

template<>
std::bitset<TAG_BITSET_SIZE> tag_combine(std::bitset<TAG_BITSET_SIZE> const & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs);

template<>
void tag_combine_inplace(std::bitset<TAG_BITSET_SIZE> & lhs, std::bitset<TAG_BITSET_SIZE> const & rhs);

template<>
std::string tag_sprint(std::bitset<TAG_BITSET_SIZE> const & tag);

#endif /* LIBDFT_TAG_TRAITS_H */

/* vim: set noet ts=4 sts=4 : */

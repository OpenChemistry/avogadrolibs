/// @file
/// @brief PEGTL-based CIF parser with pluggable action handlers and Document construction.
///
/// This header provides the complete CIF parsing infrastructure:
/// - PEG grammar rules for CIF 1.1 syntax (namespace `rules`)
/// - Customizable action handlers (templates specializing `Action<Rule>`)
/// - Built-in actions that construct an in-memory Document
/// - Entry points: read_file(), read_memory(), read_cstream(), read_istream(), read()
///
/// For high-level parsing of standard formats (mmCIF, plain CIF), prefer read_cif.hpp.

// Copyright 2017 Global Phasing Ltd.
//
// CIF parser (based on PEGTL) with pluggable actions,
// and a set of actions that prepare Document.
// To just read the CIF format, include read_cif.hpp instead.

#ifndef GEMMI_CIF_HPP_
#define GEMMI_CIF_HPP_
#include <cassert>
#include <cstdio>     // for FILE
#include <iosfwd>     // for size_t, istream
#include <string>

#include "third_party/tao/pegtl.hpp" // IWYU pragma: keep
//#include "third_party/tao/pegtl/contrib/tracer.hpp"  // for debugging

#include "cifdoc.hpp" // for Document, etc
#include "fileutil.hpp" // for CharArray, file_open

#if defined(_MSC_VER)
#pragma warning(push)
// warning C4244: an integer type is converted to a smaller integer type
#pragma warning(disable: 4244)
// warning C4267: conversion from 'size_t' to 'type', possible loss of data
#pragma warning(disable: 4267)
#endif

namespace gemmi {
namespace cif {
using std::size_t;
namespace pegtl = tao::pegtl;


// **** grammar rules, named similarly as in the CIF 1.1 spec ****
namespace rules {

  template<int TableVal> struct lookup_char {
    using analyze_t = pegtl::analysis::generic<pegtl::analysis::rule_type::ANY>;
    template<typename Input> static bool match(Input& in) {
      if (!in.empty() && cif::char_table(in.peek_char()) == TableVal) {
        if (TableVal == 2)  // this set includes new-line
          in.bump(1);
        else
          in.bump_in_this_line(1);
        return true;
      }
      return false;
    }
  };

  // (letter) refers to sections in Table 2.2.7.1 in Vol.G of ITfC (2006).

  // (g) Character sets.
  // OrdinaryCharacter: ! % &  ()*+,-./0-9:  <=>?@A-Z[]  \ ^  `a-z{|}~
  using ordinary_char = lookup_char<1>;

  using ws_char = lookup_char<2>;

  // !"#$%&'()*+,-./0-9:;<=>?@A-Z[\]^_`a-z{|}~
  struct nonblank_ch : pegtl::range<'!', '~'> {};

  // ascii space is just before '!'
  struct anyprint_ch : pegtl::ranges<' ', '~', '\t'> {};


  // (f) White space and comments.
  struct comment : pegtl::if_must<pegtl::one<'#'>, pegtl::until<pegtl::eolf>>{};
  struct whitespace : pegtl::plus<pegtl::sor<ws_char, comment>> {};
  struct ws_or_eof : pegtl::sor<whitespace, pegtl::eof> {};

  // (b) Reserved words.
  struct str_data : TAOCPP_PEGTL_ISTRING("data_") {};
  struct str_loop : pegtl::seq<TAOCPP_PEGTL_ISTRING("loop_"), pegtl::at<ws_or_eof>> {};
  struct str_global : pegtl::seq<TAOCPP_PEGTL_ISTRING("global_"), pegtl::at<ws_or_eof>> {};
  struct str_save : TAOCPP_PEGTL_ISTRING("save_") {};
  struct str_stop : pegtl::seq<TAOCPP_PEGTL_ISTRING("stop_"), pegtl::at<ws_or_eof>> {};
  struct keyword : pegtl::sor<str_data, str_loop, str_global,
                              str_save, str_stop> {};

  // (e) Character strings and text fields.
  template<typename Q>
  struct endq : pegtl::seq<Q, pegtl::at<pegtl::sor<
                                          pegtl::one<' ','\n','\r','\t','#'>,
                                          pegtl::eof>>> {};
  // strict rule would be:
  // template <typename Q> struct quoted_tail : until<endq<Q>, anyprint_ch> {};
  // but it was relaxed after PDB accepted 5q1h with non-ascii character
  template<typename Q>
  struct quoted_tail : pegtl::until<endq<Q>, pegtl::not_one<'\n'>> {};
  template<typename Q>
  struct quoted : pegtl::if_must<Q, quoted_tail<Q>> {};
  struct singlequoted : quoted<pegtl::one<'\''>> {};
  struct doublequoted : quoted<pegtl::one<'"'>> {};
  struct field_sep : pegtl::seq<pegtl::bol, pegtl::one<';'>> {};
  // CIF 2.0 requires whitespace after text field, so it'd be:
  // until<endq<field_sep>> instead of until<field_sep>.
  struct textfield : pegtl::if_must<field_sep, pegtl::until<field_sep>> {};
  struct unquoted : pegtl::seq<pegtl::not_at<keyword>,
                               pegtl::not_at<pegtl::one<'_','$','#'>>,
                               pegtl::plus<nonblank_ch>> {};

  // (a) Basic structure of CIF. (c) Tags and values.
  // datablockname in STAR/CIF should not be empty, but we made an exception
  // for RELION which writes blocks starting with bare data_
  struct datablockname : pegtl::star<nonblank_ch> {};
  struct datablockheading : pegtl::sor<pegtl::seq<str_data, datablockname>, str_global> {};
  struct tag : pegtl::seq<pegtl::one<'_'>, pegtl::plus<nonblank_ch>> {};
  // unquoted value made of ordinary characters only - for a typical mmCIF file
  // it is faster to check it first even if we backtrack on some values_.
  struct simunq : pegtl::seq<pegtl::plus<ordinary_char>, pegtl::at<ws_char>> {};
  struct value : pegtl::sor<simunq, singlequoted, doublequoted,
                            textfield, unquoted> {};
  struct item_tag : tag {};
  struct item_value : value {};
  struct loop_tag : tag {};
  struct loop_value : value {};
  struct loop_end : pegtl::opt<str_stop, ws_or_eof> {};
  struct loop : pegtl::if_must<str_loop,
                  whitespace,
                  pegtl::plus<pegtl::seq<loop_tag, whitespace, pegtl::discard>>,
                  pegtl::sor<pegtl::plus<pegtl::seq<loop_value, ws_or_eof,
                                                    pegtl::discard>>,
                             // handle incorrect CIF with empty loop
                             pegtl::at<pegtl::sor<keyword, pegtl::eof>>>,
                  loop_end> {};
  struct missing_value : pegtl::bol {};
  struct dataitem : pegtl::if_must<item_tag, whitespace,
                                   pegtl::if_then_else<item_value, ws_or_eof,
                                                       missing_value>,
                                   pegtl::discard> {};
  struct framename : pegtl::plus<nonblank_ch> {};
  struct endframe : str_save {};
  struct frame : pegtl::if_must<str_save, framename, whitespace,
                                pegtl::star<pegtl::sor<dataitem, loop>>,
                                endframe, ws_or_eof> {};
  struct datablock : pegtl::seq<datablockheading, ws_or_eof,
                             pegtl::star<pegtl::sor<dataitem, loop, frame>>> {};
  struct content : pegtl::plus<datablock> {};
  struct file : pegtl::seq<pegtl::opt<whitespace>,
                           pegtl::if_must<pegtl::not_at<pegtl::eof>,
                                          content, pegtl::eof>> {};
  struct one_block : pegtl::seq<pegtl::opt<whitespace>,
                                pegtl::if_must<pegtl::not_at<pegtl::eof>, datablock>> {};


} // namespace rules


// **** error messages ****

template<typename Rule> const std::string& error_message() {
  static const std::string s = "parse error";
  return s;
}
#define error_msg(rule, msg) \
  template<> inline const std::string& error_message<rule>() { \
    static const std::string s = msg; \
    return s; \
  }
error_msg(rules::quoted_tail<pegtl::one<'\''>>, "unterminated 'string'")
error_msg(rules::quoted_tail<pegtl::one<'"'>>, "unterminated \"string\"")
error_msg(pegtl::until<rules::field_sep>, "unterminated text field")
error_msg(rules::framename, "unnamed save_ frame")
error_msg(rules::content, "expected block header (data_)")
#undef error_msg

template<typename Rule> struct Errors : public pegtl::normal<Rule> {
  template<typename Input, typename ... States>
  static void raise(const Input& in, States&& ...) {
    throw pegtl::parse_error(error_message<Rule>()
                           //+ " matching " + pegtl::internal::demangle<Rule>()
                             , in);
  }
};

// **** parsing actions that fill the storage ****

template<typename Rule> struct Action : pegtl::nothing<Rule> {};

// We don't store comments here. We don't have a proper storage for comments.
// They can be stored as Items, but this leaves out comments before
// the first block, comments inside loops, or between tag and value.
// Additionally, a comment after a loop cannot be processed immediately
// b/c at that point we don't know if the loop is finished yet.
// If we were to store (a subset of) comments, we'd need to check first
// how it affects performance.
//template<> struct Action<rules::comment> {
//  template<typename Input> static void apply(const Input& in, Document& out) {
//  }
//};

template<> struct Action<rules::datablockname> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    out.blocks.emplace_back(in.string());
    Block& block = out.blocks.back();
    // Empty block name (just data_ ) is not STAR/CIF conformant,
    // but it's written by RELION and buccaneer; we must support it.
    if (block.name.empty())
      block.name += ' ';
    out.items_ = &block.items;
  }
};
template<> struct Action<rules::str_global> {
  template<typename Input> static void apply(const Input&, Document& out) {
    out.blocks.emplace_back();
    out.items_ = &out.blocks.back().items;
  }
};
template<> struct Action<rules::framename> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    out.items_->emplace_back(FrameArg{in.string()});
    out.items_->back().line_number = in.iterator().line;
    out.items_ = &out.items_->back().frame.items;
  }
};
template<> struct Action<rules::endframe> {
  template<typename Input> static void apply(const Input&, Document& out) {
    out.items_ = &out.blocks.back().items;
  }
};
template<> struct Action<rules::item_tag> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    out.items_->emplace_back(in.string());
    out.items_->back().line_number = in.iterator().line;
  }
};
template<> struct Action<rules::item_value> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    Item& last_item = out.items_->back();
    assert(last_item.type == ItemType::Pair);
    last_item.pair[1] = in.string();
  }
};
template<> struct Action<rules::str_loop> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    out.items_->emplace_back(LoopArg{});
    out.items_->back().line_number = in.iterator().line;
  }
};
template<> struct Action<rules::loop_tag> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    Item& last_item = out.items_->back();
    assert(last_item.type == ItemType::Loop);
    last_item.loop.tags.emplace_back(in.string());
  }
};
template<> struct Action<rules::loop_value> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    Item& last_item = out.items_->back();
    assert(last_item.type == ItemType::Loop);
    last_item.loop.values.emplace_back(in.string());
  }
};
template<> struct Action<rules::loop> {
  template<typename Input> static void apply(const Input& in, Document& out) {
    Item& last_item = out.items_->back();
    assert(last_item.type == ItemType::Loop);
    const Loop& loop = last_item.loop;
    if (loop.values.size() % loop.tags.size() != 0)
      throw pegtl::parse_error(
          "Wrong number of values in loop " + loop.common_prefix() + "*",
          in);
  }
};


/// @brief Parse CIF content from an input, populating a Document.
/// @tparam Input PEGTL input type (e.g., pegtl::file_input, pegtl::memory_input).
/// @param d Document to populate with parsed blocks and items.
/// @param in PEGTL input object.
/// @throws pegtl::parse_error on syntax errors.
template<typename Input> void parse_input(Document& d, Input&& in) {
  pegtl::parse<rules::file, Action, Errors>(in, d);
}

/// @brief Read a complete CIF file and return a Document.
/// @tparam Input PEGTL input type.
/// @param in PEGTL input object with a source() method.
/// @param check_level Validation strictness: 0=no checks, 1=missing values & duplicates, 2=also empty loops.
/// @return Fully parsed Document.
/// @throws pegtl::parse_error on syntax errors.
/// @throws std::runtime_error on validation failures (check_level > 0).
template<typename Input> Document read_input(Input&& in, int check_level=1) {
  Document doc;
  doc.source = in.source();
  parse_input(doc, in);
  if (check_level > 0) {
    check_for_missing_values(doc);
    check_for_duplicates(doc);
    if (check_level > 1) {
      for (const cif::Block& block : doc.blocks) {
        if (block.name == " ")
          fail(doc.source + ": missing block name (bare data_)");
        check_empty_loops(block, doc.source);
      }
    }
  }
  return doc;
}

/// @brief Parse a single CIF data block and add it to a Document.
/// @tparam Input PEGTL input type.
/// @param d Document to append to.
/// @param in PEGTL input.
/// @return Byte offset after parsing the block.
/// @throws pegtl::parse_error on syntax errors.
template<typename Input>
size_t parse_one_block(Document& d, Input&& in) {
  pegtl::parse<rules::one_block, Action, Errors>(in, d);
  return in.byte();
}

// pegtl::file_input may use mmap and be faster, but does not work
// on Windows with Unicode filenames.
#if defined(_WIN32)
#define GEMMI_CIF_FILE_INPUT(in, path) \
  tao::pegtl::read_input<> in(gemmi::file_open(path.c_str(), "rb").release(), path)
#else
#define GEMMI_CIF_FILE_INPUT(in, path) \
  tao::pegtl::file_input<> in(path)
#endif

/// @brief Read a CIF file from disk.
/// @param filename Path to the CIF file.
/// @param check_level Validation level (0-2).
/// @return Parsed Document.
/// @throws std::runtime_error if file cannot be opened.
/// @throws pegtl::parse_error on syntax errors.
inline Document read_file(const std::string& filename, int check_level=1) {
  GEMMI_CIF_FILE_INPUT(in, filename);
  return read_input(in, check_level);
}

/// @brief Read CIF from memory.
/// @param data Pointer to CIF content (need not be null-terminated).
/// @param size Number of bytes to parse.
/// @param name Label for error messages (e.g., "buffer").
/// @param check_level Validation level (0-2).
/// @return Parsed Document.
/// @throws pegtl::parse_error on syntax errors.
inline Document read_memory(const char* data, size_t size, const char* name, int check_level=1) {
  pegtl::memory_input<> in(data, size, name);
  return read_input(in, check_level);
}

/// @brief Read CIF from a C FILE stream.
/// @param f Open FILE pointer (e.g., stdin, or result of fopen()).
/// @param bufsize Buffering size for reading (e.g., 16*1024).
/// @param name Label for error messages.
/// @param check_level Validation level (0-2).
/// @return Parsed Document.
/// @throws pegtl::parse_error on syntax errors.
inline Document read_cstream(std::FILE *f, size_t bufsize, const char* name, int check_level=1) {
  pegtl::cstream_input<> in(f, bufsize, name);
  return read_input(in, check_level);
}

/// @brief Read CIF from a C++ std::istream.
/// @param is Input stream (e.g., std::ifstream, std::cin).
/// @param bufsize Buffering size (e.g., 16*1024).
/// @param name Label for error messages.
/// @param check_level Validation level (0-2).
/// @return Parsed Document.
/// @throws pegtl::parse_error on syntax errors.
inline Document read_istream(std::istream &is, size_t bufsize, const char* name,
                             int check_level=1) {
  pegtl::istream_input<> in(is, bufsize, name);
  return read_input(in, check_level);
}


template<typename Rule> struct CheckAction : pegtl::nothing<Rule> {};

template<> struct CheckAction<rules::missing_value> {
  template<typename Input> static void apply(const Input& in) {
    throw pegtl::parse_error("tag without value", in);
  }
};

/// @brief Try parsing CIF without validation or error throwing.
/// @tparam Input PEGTL input type.
/// @param in PEGTL input.
/// @param msg Optional pointer to store error message (if parsing fails).
/// @return true if parse succeeded, false otherwise.
template<typename Input> bool try_parse(Input&& in, std::string* msg) {
  try {
    return pegtl::parse<rules::file, CheckAction, Errors>(in);
  } catch (pegtl::parse_error& e) {
    if (msg)
      *msg = e.what();
    return false;
  }
}

/// @brief Read CIF from a file or stream, handling compression transparently.
/// @tparam T Type with methods: uncompress_into_buffer(), is_stdin(), is_compressed(), path().
/// (Traits matching BasicInput and MaybeGzipped wrappers in Gemmi.)
/// @param input Input wrapper (handles gzip, bzip2, and plain files).
/// @param check_level Validation level (0-2).
/// @return Parsed Document.
/// @throws pegtl::parse_error on syntax errors.
template<typename T>
Document read(T&& input, int check_level=1) {
  if (CharArray mem = input.uncompress_into_buffer())
    return read_memory(mem.data(), mem.size(), input.path().c_str(), check_level);
  if (input.is_stdin())
    return read_cstream(stdin, 16*1024, "stdin", check_level);
  return read_file(input.path(), check_level);
}

/// @brief Check CIF syntax without building a Document.
/// @tparam T Type with uncompress_into_buffer() and path() methods.
/// @param input Input wrapper.
/// @param msg Optional pointer to store error message.
/// @return true if syntax is valid, false otherwise.
template<typename T>
bool check_syntax(T&& input, std::string* msg) {
  if (CharArray mem = input.uncompress_into_buffer()) {
    pegtl::memory_input<> in(mem.data(), mem.size(), input.path());
    return try_parse(in, msg);
  }
  GEMMI_CIF_FILE_INPUT(in, input.path());
  return try_parse(in, msg);
}

/// @brief Read one CIF block from a file or stream into an existing Document.
/// @tparam T Type with is_compressed(), is_stdin(), uncompress_into_buffer(size_t), path() methods.
/// @param d Document to append block to.
/// @param input Input wrapper.
/// @param limit Max bytes to read from compressed file (0 = no limit).
/// @return Byte offset after parsing the block.
/// @throws pegtl::parse_error on syntax errors.
template<typename T>
size_t read_one_block(Document& d, T&& input, size_t limit) {
  if (input.is_compressed()) {
    CharArray mem = input.uncompress_into_buffer(limit);
    return parse_one_block(d, pegtl::memory_input<>(mem.data(), mem.size(),
                                                    input.path().c_str()));
  }
  if (input.is_stdin())
    return parse_one_block(d, pegtl::cstream_input<>(stdin, 16*1024, "stdin"));
  GEMMI_CIF_FILE_INPUT(in, input.path());
  return parse_one_block(d, std::move(in));
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace cif
} // namespace gemmi
#endif

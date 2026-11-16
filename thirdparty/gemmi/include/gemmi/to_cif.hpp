// Copyright 2017 Global Phasing Ltd.

/// @file
/// @brief Writing CIF documents to output streams with configurable formatting.

#ifndef GEMMI_TO_CIF_HPP_
#define GEMMI_TO_CIF_HPP_

#include <ostream>
#include "cifdoc.hpp"

namespace gemmi {
namespace cif {

/// Deprecated output formatting style. Use cif::WriteOptions instead.
///
/// This enum is provided for backward compatibility. Each style
/// corresponds to a particular WriteOptions configuration.
enum class Style {
  Simple,       ///< Standard CIF format (default)
  NoBlankLines, ///< Compact: no blank lines between categories
  PreferPairs,  ///< Write single-row loops as pairs
  Pdbx,         ///< PreferPairs + put '#' (empty comments) between categories
  Indent35,     ///< Start values in pairs from 35th column
  Aligned,      ///< Align columns in loops to fixed width
};

/// Options for writing CIF output.
///
/// Controls formatting, alignment, and output style of CIF documents.
struct WriteOptions {
  /// Write single-row loops as tag-value pairs instead of loop constructs.
  bool prefer_pairs = false;
  /// Omit blank lines between categories (keep only between blocks).
  bool compact = false;
  /// Insert '#' (empty comment lines) before and after categories.
  /// This is a non-standard CIF extension.
  bool misuse_hash = false;
  /// Width reserved for tags in pairs (0=no alignment, typical value 33-34).
  /// If set, values start at column (align_pairs + 1).
  /// Example: align_pairs=33 starts values at column 35.
  std::uint16_t align_pairs = 0;
  /// Maximum column width in loops when aligning (0=no alignment).
  /// If non-zero, all columns are padded to at most this width.
  /// This produces more compact, readable loop output.
  std::uint16_t align_loops = 0;

  WriteOptions() {}

  /// Implicit conversion from deprecated Style enum (for backward compatibility).
  ///
  /// @param style Legacy Style enum value to convert
  WriteOptions(Style style) {
    switch (style) {
      case Style::Simple:
        break;
      case Style::NoBlankLines:
        compact = true;
        break;
      case Style::PreferPairs:
        prefer_pairs = true;
        break;
      case Style::Pdbx:
        prefer_pairs = true;
        misuse_hash = true;
        break;
      case Style::Indent35:
        align_pairs = 33;
        break;
      case Style::Aligned:
        align_pairs = 33;
        align_loops = 30;
        break;
    }
  }

  /// Return a human-readable string representation of active options.
  ///
  /// @return Comma-separated list of enabled options (e.g., "prefer_pairs,compact")
  std::string str() const {
    std::string s;
    if (prefer_pairs)
      s += "prefer_pairs,";
    if (compact)
      s += "compact,";
    if (misuse_hash)
      s += "misuse_hash,";
    if (align_pairs != 0)
      s += "align_pairs=" + std::to_string(align_pairs) + ",";
    if (align_loops != 0)
      s += "align_loops=" + std::to_string(align_loops) + ",";
    if (!s.empty())
      s.pop_back();
    return s;
  }
};

/// Buffered output stream wrapper for efficient CIF writing.
///
/// Wraps std::ostream with a 4KB buffer to significantly improve I/O performance
/// when writing CIF documents. The buffer is automatically flushed on destruction
/// and when it fills.
class BufOstream {
public:
  /// Construct a buffered output stream.
  /// @param os_ The underlying std::ostream to write to
  explicit BufOstream(std::ostream& os_) : os(os_), ptr(buf) {}

  /// Destructor flushes remaining buffered data.
  ~BufOstream() { flush(); }

  /// Flush all buffered data to the underlying stream.
  void flush() {
    os.write(buf, ptr - buf);
    ptr = buf;
  }

  /// Write data to the buffer, flushing if necessary.
  /// @param s    Pointer to data to write
  /// @param len  Number of bytes to write
  void write(const char* s, size_t len) {
    constexpr int margin = sizeof(buf) - 512;
    if (ptr - buf + len > margin) {
      flush();
      if (len > margin) {
        os.write(s, len);
        return;
      }
    }
    std::memcpy(ptr, s, len);
    ptr += len;
  }

  /// Write a string to the buffer.
  /// @param s The string to write
  void operator<<(const std::string& s) {
    write(s.c_str(), s.size());
  }

  // Note: The following functions assume writes are small (<512 bytes).
  // No buffer boundary check is performed for performance.

  /// Write a single character to the buffer.
  /// @param c The character to write
  void put(char c) {
    *ptr++ = c;
  }

  /// Write n space characters to the buffer (for padding/alignment).
  /// @param n Number of spaces to write
  void pad(size_t n) {
    std::memset(ptr, ' ', n);
    ptr += n;
  }
private:
  std::ostream& os;
  // increasing buffer to 8kb or 64kb doesn't make significant difference
  char buf[4096];
  char* ptr;
};

// Note: CIF files are read in binary mode. Text fields with \r\n line endings
// are normalized to \n when writing to avoid duplication in Windows text mode.
/// Write a text field, normalizing \\r\\n to \\n.
/// @param os    Buffered output stream
/// @param value The text field value to write
inline void write_text_field(BufOstream& os, const std::string& value) {
  for (size_t pos = 0, end = 0; end != std::string::npos; pos = end + 1) {
    end = value.find("\r\n", pos);
    size_t len = (end == std::string::npos ? value.size() : end) - pos;
    os.write(value.c_str() + pos, len);
  }
}

inline void write_out_pair(BufOstream& os, const std::string& name,
                           const std::string& value, WriteOptions options) {
  os << name;
  if (is_text_field(value)) {
    os.put('\n');
    write_text_field(os, value);
  } else {
    if (name.size() + value.size() > 120) {
      os.put('\n');
    } else {
      os.put(' ');
      if (name.size() < options.align_pairs)
        os.pad(options.align_pairs - name.size());
    }
    os << value;
  }
  os.put('\n');
}

inline void write_out_loop(BufOstream& os, const Loop& loop, WriteOptions options) {
  if (loop.values.empty())
    return;
  if (options.prefer_pairs && loop.length() == 1) {
    for (size_t i = 0; i != loop.tags.size(); ++i)
      write_out_pair(os, loop.tags[i], loop.values[i], options);
    return;
  }
  // tags
  os.write("loop_", 5);
  for (const std::string& tag : loop.tags) {
    os.put('\n');
    os << tag;
  }
  // values
  size_t ncol = loop.tags.size();

  std::vector<size_t> col_width(ncol, 0);
  if (options.align_loops > 0) {
    size_t col = 0;
    for (const std::string& val : loop.values) {
      if (!is_text_field(val))
        col_width[col] = std::max(col_width[col], val.size());
      if (++col == ncol)
        col = 0;
    }
    for (size_t& w : col_width)
      w = std::min(w, (size_t)options.align_loops);
  }

  size_t col = 0;
  bool need_new_line = true;
  for (const std::string& val : loop.values) {
    bool text_field = is_text_field(val);
    os.put(need_new_line || text_field ? '\n' : ' ');
    need_new_line = text_field;
    if (text_field)
      write_text_field(os, val);
    else
      os << val;
    if (col != ncol - 1) {
      if (val.size() < col_width[col])
        os.pad(col_width[col] - val.size());
      ++col;
    } else {
      col = 0;
      need_new_line = true;
    }
  }
  os.put('\n');
}

inline void write_out_item(BufOstream& os, const Item& item, WriteOptions options) {
  switch (item.type) {
    case ItemType::Pair:
      write_out_pair(os, item.pair[0], item.pair[1], options);
      break;
    case ItemType::Loop:
      write_out_loop(os, item.loop, options);
      break;
    case ItemType::Frame:
      os.write("save_", 5);
      os << item.frame.name;
      os.put('\n');
      for (const Item& inner_item : item.frame.items)
        write_out_item(os, inner_item, options);
      os.write("save_\n", 6);
      break;
    case ItemType::Comment:
      os << item.pair[1];
      os.put('\n');
      break;
    case ItemType::Erased:
      break;
  }
}

inline bool should_be_separated_(const Item& a, const Item& b) {
  if (a.type == ItemType::Comment || b.type == ItemType::Comment)
    return false;
  if (a.type != ItemType::Pair || b.type != ItemType::Pair)
    return true;
  // check if we have mmcif-like tags from different categories
  auto adot = a.pair[0].find('.');
  if (adot == std::string::npos)
    return false;
  auto bdot = b.pair[0].find('.');
  return adot != bdot || a.pair[0].compare(0, adot, b.pair[0], 0, adot) != 0;
}

/// Write a single CIF block to an output stream.
///
/// Writes a CIF data block with the specified formatting options.
///
/// @param os_     Output stream to write to
/// @param block   The CIF block to write
/// @param options Formatting options (see WriteOptions documentation)
inline void write_cif_block_to_stream(std::ostream& os_, const Block& block,
                                      WriteOptions options=WriteOptions()) {
  BufOstream os(os_);
  os.write("data_", 5);
  os << block.name;
  os.put('\n');
  if (options.misuse_hash)
    os.write("#\n", 2);
  const Item* prev = nullptr;
  for (const Item& item : block.items) {
    if (item.type == ItemType::Erased)
      continue;
    if (prev && !options.compact && should_be_separated_(*prev, item)) {
      if (options.misuse_hash)
        os.put('#');
      os.put('\n');
    }
    write_out_item(os, item, options);
    prev = &item;
  }
  if (options.misuse_hash)
    os.write("#\n", 2);
}

/// Write a CIF document to an output stream.
///
/// Writes a complete CIF document with all its blocks, using the specified
/// formatting options. Blocks are separated by blank lines for readability.
///
/// @param os      Output stream to write to
/// @param doc     The CIF document to write
/// @param options Formatting options (see WriteOptions documentation)
inline void write_cif_to_stream(std::ostream& os, const Document& doc,
                                WriteOptions options=WriteOptions()) {
  bool first = true;
  for (const Block& block : doc.blocks) {
    if (!first)
      os.put('\n'); // extra blank line for readability
    write_cif_block_to_stream(os, block, options);
    first = false;
  }
}

} // namespace cif
} // namespace gemmi

#endif

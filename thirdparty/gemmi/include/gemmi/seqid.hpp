/// @file
/// @brief Sequence/residue identifiers including insertion codes.
///
/// Provides SeqId (sequence number + insertion code), ResidueId (with segment),
/// and AtomAddress (chain + residue + atom) for unambiguous atom/residue reference.

// Copyright 2017 Global Phasing Ltd.
//
// SeqId -- residue number and insertion code together.

#ifndef GEMMI_SEQID_HPP_
#define GEMMI_SEQID_HPP_

#include <climits>    // for INT_MIN
#include <cstdlib>    // for strtol
#include <stdexcept>  // for invalid_argument
#include <string>
#include "util.hpp"   // for cat

namespace gemmi {

/// @brief Optional integer with a sentinel "not-set" value.
/// @tparam N Sentinel value indicating "not set" state.
/// @details Provides None enum value and has_value() check analogous to std::optional.
template<int N> struct OptionalInt {
  enum { None=N }; ///< Sentinel value indicating "not set"
  int value = None; ///< Stored integer or sentinel

  OptionalInt() = default;
  /// @brief Construct with integer value.
  OptionalInt(int n) : value(n) {}

  /// @brief Check if value is set (not sentinel).
  bool has_value() const { return value != None; }

  /// @brief Convert to string, or fallback character if not set.
  /// @param null Fallback character when value is not set (default '?').
  /// @return String representation of integer or single fallback character.
  std::string str(char null='?') const {
    return has_value() ? std::to_string(value) : std::string(1, null);
  }

  OptionalInt& operator=(int n) { value = n; return *this; }
  bool operator==(const OptionalInt& o) const { return value == o.value; }
  bool operator!=(const OptionalInt& o) const { return value != o.value; }

  /// @brief Less-than comparison (both values must be set).
  bool operator<(const OptionalInt& o) const {
    return has_value() && o.has_value() && value < o.value;
  }

  bool operator==(int n) const { return value == n; }
  bool operator!=(int n) const { return value != n; }

  /// @brief Add two OptionalInt values (propagates "not set" state).
  OptionalInt operator+(OptionalInt o) const {
    return OptionalInt(has_value() && o.has_value() ? value + o.value : N);
  }

  /// @brief Subtract two OptionalInt values (propagates "not set" state).
  OptionalInt operator-(OptionalInt o) const {
    return OptionalInt(has_value() && o.has_value() ? value - o.value : N);
  }

  OptionalInt& operator+=(int n) { if (has_value()) value += n; return *this; }
  OptionalInt& operator-=(int n) { if (has_value()) value -= n; return *this; }
  explicit operator int() const { return value; }

  /// @brief Check if value is set (true if has_value()).
  explicit operator bool() const { return has_value(); }

  // Partial compatibility with C++17 std::optional
  using value_type = int; ///< Type alias for value
  int& operator*() { return value; } ///< Dereference to stored value
  const int& operator*() const { return value; } ///< Const dereference
  int& emplace(int n) { value = n; return value; } ///< Set value and return reference
  void reset() noexcept { value = None; } ///< Set to not-set state
};

/// @brief Residue sequence identifier: sequence number plus insertion code.
///
/// Corresponds to the combination of _atom_site.auth_seq_id (num) and
/// _atom_site.pdbx_PDB_ins_code (icode) in mmCIF, or RESSEQ + ICODE in PDB format.
struct SeqId {
  using OptionalNum = OptionalInt<INT_MIN>; ///< Optional sequence number (INT_MIN = not set)

  OptionalNum num;   ///< Residue sequence number (0 and negative allowed; INT_MIN = unset)
  char icode = ' ';  ///< Insertion code (' ' = no insertion code; 'A'-'Z' typical)

  SeqId() = default;

  /// @brief Construct with sequence number and insertion code.
  /// @param num_ Sequence number (0 is valid; unset via OptionalNum).
  /// @param icode_ Insertion code (' ' for none, typically 'A'-'Z').
  SeqId(int num_, char icode_) { num = num_; icode = icode_; }

  /// @brief Construct with OptionalNum and insertion code.
  SeqId(OptionalNum num_, char icode_) { num = num_; icode = icode_; }

  /// @brief Parse SeqId from string (e.g., "12", "12A", "12b").
  /// @param str String containing sequence number and optional insertion code.
  /// @throws std::invalid_argument if string is malformed.
  explicit SeqId(const std::string& str) {
    char* endptr;
    num = std::strtol(str.c_str(), &endptr, 10);
    if (endptr == str.c_str() || (*endptr != '\0' && endptr[1] != '\0'))
      throw std::invalid_argument("Not a seqid: " + str);
    icode = (*endptr | 0x20); // Convert to lowercase for consistency
  }

  /// @brief Equality comparison (case-insensitive insertion code).
  /// @details Two SeqIds are equal if num equals and insertion codes match
  ///          (ignoring case). Space equals space, 'a' equals 'A', etc.
  bool operator==(const SeqId& o) const {
    return num == o.num && ((icode ^ o.icode) & ~0x20) == 0;
  }

  bool operator!=(const SeqId& o) const { return !operator==(o); }

  /// @brief Less-than ordering by (num, icode).
  /// @details Orders first by sequence number, then by insertion code.
  bool operator<(const SeqId& o) const {
    return (*num * 256 + icode) < (*o.num * 256 + o.icode);
  }

  bool operator<=(const SeqId& o) const { return !(o < *this); }

  /// @brief Check if insertion code is present (not space).
  /// @return True if icode != ' ', false otherwise.
  char has_icode() const { return icode != ' '; }

  /// @brief Convert to string representation (e.g., "12", "12A").
  /// @param dot_before_icode If true, insert dot before icode (e.g., "12.A").
  /// @return String with sequence number and optional insertion code.
  std::string str(bool dot_before_icode=false) const {
    std::string r = num.str();
    if (icode != ' ') {
      if (dot_before_icode)
        r += '.';
      r += icode;
    }
    return r;
  }
};

/// @brief Complete residue identifier: sequence ID + segment + residue name.
/// @details Uniquely identifies a residue within a chain. Includes segment ID
/// (segid) from PDB format for structures with multiple segments.
struct ResidueId {
  SeqId seqid;              ///< Sequence number + insertion code
  std::string segment;      ///< Segment identifier (up to 4 chars, usually empty)
  std::string name;         ///< Residue name (3-letter code: ALA, GLY, HOH, etc.)

  /// @brief Get grouping key for iterator operations.
  /// @return SeqId for use in grouping/comparison operations.
  SeqId group_key() const { return seqid; }

  /// @brief Full equality: seqid, segment, and name all match.
  /// @param o ResidueId to compare with.
  /// @return True if all three fields match exactly.
  bool matches(const ResidueId& o) const {
    return seqid == o.seqid && segment == o.segment && name == o.name;
  }

  /// @brief Equality ignoring segment: seqid and name match.
  /// @param o ResidueId to compare with.
  /// @return True if seqid and name match (segment ignored).
  bool matches_noseg(const ResidueId& o) const {
    return seqid == o.seqid && name == o.name;
  }

  /// @brief Equality operator uses full matches() check.
  bool operator==(const ResidueId& o) const { return matches(o); }

  /// @brief Convert to string representation (e.g., "12(ALA)").
  std::string str() const { return cat(seqid.str(), '(', name, ')'); }
};

/// @brief Format atom address as string.
/// @param chain_name Chain identifier.
/// @param res_id Residue identifier (number, insertion code, name, segment).
/// @param atom_name Atom name (e.g., "CA", "CB").
/// @param altloc Alternate location code ('\0' = no alternate).
/// @param as_cid If true, format as mmCIF CID (// prefix, dot before icode).
///               If false, format as PDB style.
/// @return String representation of atom location (e.g., "A/ALA 12/CA" or "//A/12/CA").
inline std::string atom_str(const std::string& chain_name,
                            const ResidueId& res_id,
                            const std::string& atom_name,
                            char altloc,
                            bool as_cid=false) {
  std::string r = as_cid ? "//" + chain_name : chain_name;
  r += '/';
  if (!as_cid) {
    r += res_id.name;
    r += ' ';
  }
  r += res_id.seqid.str(as_cid);
  if (as_cid && atom_name == "null")
    return r;
  r += '/';
  r += atom_name;
  if (altloc) {
    r += as_cid ? ':' : '.';
    r += altloc;
  }
  return r;
}

/// @brief Complete atom address: chain + residue + atom + alternate location.
/// @details Fully specifies an atom in the structure (including alternate
/// conformations if altloc is set). Corresponds to an atom record in PDB/mmCIF.
struct AtomAddress {
  std::string chain_name;   ///< Chain identifier (A, B, H, L, etc.)
  ResidueId res_id;         ///< Residue identifier within chain
  std::string atom_name;    ///< Atom name (CA, CB, OD1, etc.)
  char altloc = '\0';       ///< Alternate location code ('\0' = main conformation)

  AtomAddress() = default;

  /// @brief Construct from chain, residue ID, and atom name.
  /// @param ch Chain name.
  /// @param resid Complete residue identifier.
  /// @param atom Atom name.
  /// @param alt Alternate location ('\0' = main).
  AtomAddress(const std::string& ch, const ResidueId& resid,
              const std::string& atom, char alt='\0')
    : chain_name(ch), res_id(resid), atom_name(atom), altloc(alt) {}

  /// @brief Construct from chain, sequence ID, residue name, and atom name.
  /// @param ch Chain name.
  /// @param seqid Sequence ID (number + insertion code).
  /// @param res Residue name (3-letter code).
  /// @param atom Atom name.
  /// @param alt Alternate location ('\0' = main).
  AtomAddress(const std::string& ch, const SeqId& seqid, const std::string& res,
              const std::string& atom, char alt='\0')
    : chain_name(ch), res_id({seqid, "", res}), atom_name(atom), altloc(alt) {}

  /// @brief Equality comparison (chain, residue, atom, and altloc).
  bool operator==(const AtomAddress& o) const {
    return chain_name == o.chain_name && res_id.matches(o.res_id) &&
           atom_name == o.atom_name && altloc == o.altloc;
  }

  /// @brief Convert to string representation.
  /// @return Formatted string (e.g., "A/ALA 12/CA").
  std::string str() const {
    return atom_str(chain_name, res_id, atom_name, altloc);
  }
};

} // namespace gemmi

namespace std {
template <> struct hash<gemmi::ResidueId> {
  size_t operator()(const gemmi::ResidueId& r) const {
    size_t seqid_hash = (*r.seqid.num << 7) + (r.seqid.icode | 0x20);
    return seqid_hash ^ hash<string>()(r.segment) ^ hash<string>()(r.name);
  }
};
} // namespace std

#endif

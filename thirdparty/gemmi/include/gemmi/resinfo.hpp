/// @file
/// @brief Tabulated residue information and classification.
///
/// Provides lookup table for standard PDB residues with chemical properties,
/// one-letter codes, and classifications (amino acids, nucleic acids, etc.).

// Copyright 2018 Global Phasing Ltd.
//
// List of common residues with basic data.

#ifndef GEMMI_RESINFO_HPP_
#define GEMMI_RESINFO_HPP_

#include <cstdint>  // for uint8_t
#include <string>
#include <vector>
#include "fail.hpp"

namespace gemmi {

/// @brief Classification of residue type.
/// @details Categorizes residues by chemical function and polymer type.
enum class ResidueKind : unsigned char {
  UNKNOWN = 0, ///< Unknown or unclassified residue
  AA,          ///< L-amino acid (standard protein residue)
  AAD,         ///< D-amino acid
  PAA,         ///< Proline-like amino acid (cyclic imino acid)
  MAA,         ///< Methylated amino acid (non-standard)
  RNA,         ///< Ribonucleotide (RNA)
  DNA,         ///< Deoxyribonucleotide (DNA)
  BUF,         ///< Buffer/crystallization agent (from PISA agents.dat)
  HOH,         ///< Water molecule (H2O, D2O, or hydroxide)
  PYR,         ///< Pyranose sugar (per Refmac dictionary)
  KET,         ///< Ketopyranose sugar (per Refmac dictionary)
  ELS          ///< Everything else (organic ligand, metal, etc.)
};

/// @brief Tabulated properties of a residue type.
/// @details Contains chemical and structural information for known residues.
/// Used by find_tabulated_residue() to return properties for standard residues.
struct ResidueInfo {
  char name[8];                  ///< Residue name (3-letter code: ALA, GLY, etc.)
  ResidueKind kind;              ///< Classification by type
  std::uint8_t linking_type;     ///< Polymer linking: 1=peptide, 2=nucleic, 3=both
  char one_letter_code;          ///< Standard IUPAC single-letter code (or space)
  std::uint8_t hydrogen_count;   ///< Approximate hydrogen count (for implicit H)
  float weight;                  ///< Molecular weight (Da)

  /// @brief Check if residue was found in tabulated data.
  /// @return True if kind != UNKNOWN, false otherwise.
  bool found() const { return kind != ResidueKind::UNKNOWN; }

  /// @brief Check if residue is water.
  bool is_water() const { return kind == ResidueKind::HOH; }

  /// @brief Check if residue is DNA nucleotide.
  bool is_dna() const { return kind == ResidueKind::DNA; }

  /// @brief Check if residue is RNA nucleotide.
  bool is_rna() const { return kind == ResidueKind::RNA; }

  /// @brief Check if residue is nucleic acid (DNA or RNA).
  bool is_nucleic_acid() const { return is_dna() || is_rna(); }

  /// @brief Check if residue is amino acid (any form: L, D, proline, methylated).
  bool is_amino_acid() const {
    return kind == ResidueKind::AA || kind == ResidueKind::AAD ||
           kind == ResidueKind::PAA || kind == ResidueKind::MAA;
  }

  /// @brief Check if residue is water or buffer component.
  bool is_buffer_or_water() const {
    return kind == ResidueKind::HOH || kind == ResidueKind::BUF;
  }

  /// @brief Check if residue is standard (marked in PDB with ATOM, not HETATM).
  /// @return True if uppercase one-letter code; false if lowercase/space.
  bool is_standard() const { return (one_letter_code & 0x20) == 0; }

  /// @brief Get one-letter code for FASTA output.
  /// @return Standard one-letter code if standard residue; 'X' otherwise.
  char fasta_code() const { return is_standard() ? one_letter_code : 'X'; }

  /// @brief Check if residue participates in peptide bonds.
  /// @return True if linking_type has peptide-linking bit set.
  bool is_peptide_linking() const { return (linking_type & 1); }

  /// @brief Check if residue participates in nucleic acid backbone.
  /// @return True if linking_type has nucleic acid bit set.
  bool is_na_linking() const { return (linking_type & 2); }
};

/// @brief Look up residue info by table index.
/// @param idx Index into the residue table (0 = ALA, etc.).
/// @return Reference to ResidueInfo at this index.
GEMMI_DLL ResidueInfo& get_residue_info(size_t idx);

/// @brief Find table index of named residue.
/// @param name Residue name (3-letter code, case-insensitive).
/// @return Table index, or unknown_tabulated_residue_idx() if not found.
GEMMI_DLL size_t find_tabulated_residue_idx(const std::string& name);

/// @brief Sentinel index for unknown residue in table.
/// @return Index used when residue is not found (returns ResidueInfo with kind=UNKNOWN).
constexpr size_t unknown_tabulated_residue_idx() { return 367; };

/// @brief Look up tabulated residue by name.
/// @param name Residue name (3-letter code: ALA, HOH, ATP, etc.).
/// @return ResidueInfo for the named residue, or ResidueInfo with kind UNKNOWN if the name is not in the table.
GEMMI_DLL ResidueInfo& find_tabulated_residue(const std::string& name);

/// @brief Expand one-letter code to 3-letter residue name.
/// @param c One-letter code (A-Z, case-insensitive).
/// @param kind Polymer type: AA (amino acid), RNA, or DNA.
/// @return 3-letter residue name or nullptr if code invalid for this type.
/// @details Maps standard IUPAC one-letter codes to residue names.
///          For DNA/RNA, 'T' (DNA) vs 'U' (RNA) are distinct.
inline const char* expand_one_letter(char c, ResidueKind kind) {
  static const char* names =
    // amino-acids (all letters but J are used)
    "ALA\0ASX\0CYS\0ASP\0GLU\0PHE\0GLY\0HIS\0ILE\0\0   LYS\0LEU\0MET\0"  // A-M
    "ASN\0PYL\0PRO\0GLN\0ARG\0SER\0THR\0SEC\0VAL\0TRP\0UNK\0TYR\0GLX\0"  // N-Z
    // DNA
    "DA\0 \0\0  DC\0 \0\0  \0\0  \0\0  DG\0 \0\0  DI\0 \0\0  \0\0  \0\0  \0\0  "   // A-M
    "DN\0 \0\0  \0\0  \0\0  \0\0  \0\0  DT\0 DU\0 \0\0  \0\0  \0\0  \0\0  \0\0  "; // N-Z
  c &= ~0x20;
  const char* ret = nullptr;
  if (c >= 'A' && c <= 'Z') {
    ret = &names[4 * (c - 'A')];
    if (kind == ResidueKind::AA) {
      // ret is already set
    } else if (kind == ResidueKind::DNA) {
      ret += 4 * 26;
    } else if (kind == ResidueKind::RNA && c != 'T') {
      ret += 4 * 26 + 1;
    } else {
      ret = nullptr;
    }
  }
  return (ret && *ret) ? ret : nullptr;
}

/// @brief Expand sequence of one-letter codes to 3-letter residue names.
/// @param seq String of one-letter codes (e.g., "MVLVS" for amino acids).
/// @param kind Polymer type: AA (protein), RNA, or DNA.
/// @return Vector of 3-letter residue names; entries are empty for invalid codes.
GEMMI_DLL std::vector<std::string> expand_one_letter_sequence(const std::string& seq,
                                                              ResidueKind kind);

/// @brief Deprecated: use expand_one_letter(c, ResidueKind::AA) instead.
inline const char* expand_protein_one_letter(char c) {
  return expand_one_letter(c, ResidueKind::AA);
}

/// @brief Deprecated: use expand_one_letter_sequence(s, ResidueKind::AA) instead.
GEMMI_DLL std::vector<std::string> expand_protein_one_letter_string(const std::string& s);


} // namespace gemmi
#endif

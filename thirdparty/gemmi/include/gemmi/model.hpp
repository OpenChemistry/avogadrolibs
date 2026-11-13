// Copyright 2017 Global Phasing Ltd.
//
// Data structures to store macromolecular structure models.

/// @file
/// @brief Core hierarchical data structures for macromolecular models.
///
/// This header defines the fundamental data types used throughout Gemmi to represent
/// macromolecular structures. The hierarchy is:
/// - Structure (complete 3D model with metadata)
///   - Model (NMR/ensemble models with sequential numbering)
///     - Chain (named sequences of residues)
///       - Residue (single amino acid or nucleotide)
///         - Atom (individual atomic coordinates)
///
/// It also provides helper structures and enums for handling file formats, calculation
/// flags, secondary structure, and various search/access utilities.

#ifndef GEMMI_MODEL_HPP_
#define GEMMI_MODEL_HPP_

#include <algorithm>  // for find_if, count_if, lower_bound
#include <array>
#include <bitset>
#include <iterator>   // for back_inserter
#include <map>        // for map
#include <stdexcept>  // for out_of_range
#include <string>
#include <vector>

#include "elem.hpp"
#include "fail.hpp"      // for fail
#include "unitcell.hpp"
#include "symmetry.hpp"
#include "metadata.hpp"
#include "iterator.hpp"
#include "span.hpp"      // for Span, MutableVectorSpan
#include "seqid.hpp"
#include "util.hpp"      // for join_str, vector_move_extend, in_vector
#include "chemcomp.hpp"

namespace gemmi {

namespace impl {

template<typename T>
auto get_id(const T& m) -> decltype(m.name) { return m.name; }
template<typename T>
auto get_id(const T& m) -> decltype(m.num) { return m.num; }


template<typename Vec, typename S>
auto find_iter_(Vec& vec, const S& name) {
  return std::find_if(vec.begin(), vec.end(), [&name](const auto& m) { return get_id(m) == name; });
}

template<typename T, typename S>
T* find_or_null(std::vector<T>& vec, const S& name) {
  auto it = find_iter_(vec, name);
  return it != vec.end() ? &*it : nullptr;
}

template<typename T, typename S>
T& find_or_add(std::vector<T>& vec, const S& name) {
  if (T* ret = find_or_null(vec, name))
    return *ret;
  vec.emplace_back(name);
  return vec.back();
}

template<typename Span, typename S>
typename Span::iterator find_iter(Span& span, const S& name) {
  using T = typename Span::value_type;
  auto it = find_iter_(span, name);
  if (it == span.end())
    throw std::invalid_argument(cat(
        T::what(), ' ', name, " not found (only [",
        join_str(span.begin(), span.end(), ' ', [](const T& item) { return cat(get_id(item)); }),
        "])"));
  return it;
}

template<typename Group>
typename Group::element_type& get_by_altloc(Group& group, char alt) {
  for (auto& atom : group)
    if (atom.altloc == alt)
      return atom;
  fail("No such altloc");
}

template<typename T, typename M> std::vector<T> model_subchains(M* model) {
  std::vector<T> v;
  for (auto& chain : model->chains)
    vector_move_extend(v, chain.subchains());
  return v;
}
} // namespace impl


/// @brief File format of a macromolecular model structure.
/// When passed to read_structure():
/// Unknown = guess format from the extension (default),
/// Detect = guess format from the content (read first bytes).
enum class CoorFormat : unsigned char {
  Unknown,  ///< Guess from file extension
  Detect,   ///< Guess from content/magic bytes
  Pdb,      ///< PDB format
  Mmcif,    ///< mmCIF format
  Mmjson,   ///< mmJSON format
  ChemComp  ///< Chemical component format
};

/// @brief Atom site calculation flag from mmCIF _atom_site.calc_flag.
/// Indicates how atomic coordinates and B-factors were determined.
/// Note: NoHydrogen has the same numeric value (0) as NotSet; it is used internally
/// to mark atoms that should not have riding hydrogens added.
enum class CalcFlag : signed char {
  NotSet=0,     ///< Flag not set (default)
  NoHydrogen,   ///< Internal flag: do not add riding hydrogens (same value as NotSet)
  Determined,   ///< Experimentally determined
  Calculated,   ///< Calculated or assigned from geometry
  Dummy         ///< Dummy position for QM/MM or placeholder atoms
};

/// @brief Secondary structure annotation from structure file.
enum class ResidueSs : unsigned char {
  Coil,   ///< Random coil or unassigned
  Helix,  ///< Helical conformation (alpha, 3-10, pi, etc.)
  Strand  ///< Beta strand
};

/// @brief Strand sense within a beta sheet from PDB/mmCIF structure file.
/// Distinguishes the first strand in a sheet from other strands and non-strand residues.
enum class ResidueStrandSense : signed char {
  NotStrand = 0,     ///< Not part of a beta sheet
  Parallel = 1,      ///< Parallel to the previous strand
  First = 2,         ///< First strand in a sheet
  Antiparallel = -1  ///< Antiparallel to the previous strand
};

/// @brief Options controlling PDB file parsing behavior.
struct PdbReadOptions {
  int max_line_length = 0;     ///< Maximum line length (0 = no limit)
  bool check_non_ascii = false; ///< Detect and report non-ASCII characters
  bool ignore_ter = false;      ///< Ignore TER records completely
  bool split_chain_on_ter = false; ///< Split chain at each TER record
  bool skip_remarks = false;    ///< Skip REMARK records entirely
};
// end of PdbReadOptions for mol.rst

/// @brief Recursively remove empty child elements.
/// Removes empty residues from a chain, empty chains from a model, etc.
/// Works with any type that has a @c child_type and @c children() method.
/// @tparam T Container type (Chain, Model, or Structure)
template<class T> void remove_empty_children(T& obj) {
  using Item = typename T::child_type;
  vector_remove_if(obj.children(), [](const Item& x) { return x.children().empty(); });
}

/// @brief Check if two atoms belong to the same conformer (alternate location).
/// Returns true if altloc values are compatible (either one or both unset, or identical).
/// @param altloc1 First alternate location character ('\0' means no alternate location set)
/// @param altloc2 Second alternate location character
/// @return true if atoms are in the same conformer, false otherwise
inline bool is_same_conformer(char altloc1, char altloc2) {
  return altloc1 == '\0' || altloc2 == '\0' || altloc1 == altloc2;
}

/// @brief Represents an atom site in a macromolecular structure (approximately 100 bytes).
/// Stores 3D coordinates, occupancy, atomic displacement parameters (ADP),
/// and associated metadata for a single atom.
struct Atom {
  static const char* what() { return "Atom"; }
  std::string name;              ///< Atom name (e.g., "CA", "CB", "C", "N", "O")
  char altloc = '\0';            ///< Alternate location character ('\0' = not set)
  signed char charge = 0;        ///< Formal charge in range [-8, +8]
  Element element = El::X;       ///< Atomic element
  CalcFlag calc_flag = CalcFlag::NotSet;  ///< mmCIF _atom_site.calc_flag
  char flag = '\0';              ///< Custom flag for user-defined marking
  short tls_group_id = -1;       ///< TLS group assignment (-1 = not assigned)
  int serial = 0;                ///< Atom serial number from input file
  float fraction = 0.f;          ///< Custom fractional value (e.g., Refmac ccp4_deuterium_fraction)
  Position pos;                  ///< Cartesian coordinates (x, y, z)
  float occ = 1.0f;              ///< Occupancy (0.0 to 1.0 typical; >1.0 rare)
  float b_iso = 20.0f;           ///< Isotropic B-factor (temperature factor) in Ångström²
  SMat33<float> aniso = {0, 0, 0, 0, 0, 0}; ///< Anisotropic displacement parameters U[6]

  /// @brief Get alternate location character, or fallback value if not set.
  /// @param null_char Character to return if altloc is not set ('\0')
  /// @return altloc if set, otherwise null_char
  char altloc_or(char null_char) const { return altloc ? altloc : null_char; }

  /// @brief Check if this atom belongs to the same conformer as another.
  /// @param other The other atom to compare
  /// @return true if atoms are compatible conformations
  bool same_conformer(const Atom& other) const {
    return is_same_conformer(altloc, other.altloc);
  }

  /// @brief Check if this atom matches an alternate location request.
  /// '*' matches any altloc, '\0' matches atoms without altloc.
  /// @param request Requested alternate location character
  /// @return true if this atom's altloc matches the request
  bool altloc_matches(char request) const {
    return request == '*' || altloc == '\0' || altloc == request;
  }

  /// @brief Get grouping key for UniqIter and similar iteration tools.
  /// @return The atom name
  const std::string& group_key() const { return name; }

  /// @brief Check if this atom has an alternate location assigned.
  /// @return true if altloc != '\0'
  bool has_altloc() const { return altloc != '\0'; }

  /// @brief Calculate equivalent isotropic B-factor from anisotropic U parameters.
  /// @return B_eq = (U[0] + U[1] + U[2]) * 8 * pi^2 / 3
  double b_eq() const { return u_to_b() / 3. * aniso.trace(); }

  /// @brief Check if this atom represents a hydrogen.
  /// @return true if element is H, D, or T
  bool is_hydrogen() const { return gemmi::is_hydrogen(element); }

  /// @brief Return atom name padded like in PDB format (left-aligned with space).
  /// The first two characters of the padded name make the element symbol.
  /// @return Padded atom name (up to 4 characters)
  std::string padded_name() const {
    std::string s;
    const char* el = element.uname();
    if (el[1] == '\0' &&
        (el[0] == alpha_up(name[0]) || (is_hydrogen() && alpha_up(name[0]) == 'H')) &&
        name.size() < 4)
      s += ' ';
    s += name;
    return s;
  }

  /// @brief Create a copy of this atom (shallow copy).
  /// Used in template code for hierarchical copying.
  /// @return A new Atom with identical field values
  Atom empty_copy() const { return Atom(*this); }
};

/// @brief A group of atoms sharing the same name but occupying different alternate locations.
///
/// Used to iterate over or access atoms at a single crystallographic site
/// that have been modelled in multiple conformations (alt locs).
/// @tparam AtomType Either `Atom` (mutable) or `const Atom` (immutable).
template<typename AtomType>
struct AtomGroup_ : ItemGroup<AtomType> {
  using ItemGroup<AtomType>::ItemGroup;

  /// @brief Get the atom name (same for all atoms in the group).
  /// @return Atom name, or empty string if group is empty
  std::string name() const { return !this->empty() ? this->front().name : ""; }

  /// @brief Find atom in this group by alternate location character.
  /// @param alt Alternate location character to search for
  /// @return Reference to the atom with the given altloc
  /// @throws fail() if no atom with the given altloc is found
  AtomType& by_altloc(char alt) {
    for (int i = 0; i != this->extent(); ++i) {
      AtomType* a = &this->front() + i;
      if (a->altloc == alt && (a->name == this->front().name))
        return *a;
    }
    fail("No such altloc");
  }
};

using AtomGroup = AtomGroup_<Atom>;         ///< Mutable group of atoms
using ConstAtomGroup = AtomGroup_<const Atom>; ///< Const group of atoms

/// @brief Represents a single residue (amino acid, nucleotide, or other).
/// A residue is identified by its number and insertion code (SeqId) and contains
/// multiple atoms, potentially in alternate conformations.
struct Residue : public ResidueId {
  using OptionalNum = SeqId::OptionalNum;
  static const char* what() { return "Residue"; }

  std::string subchain;   ///< mmCIF _atom_site.label_asym_id (asymmetric unit identifier)
  std::string entity_id;  ///< mmCIF _atom_site.label_entity_id (polymer/ligand/solvent classification)
  OptionalNum label_seq;  ///< mmCIF _atom_site.label_seq_id (canonical sequence numbering)
  EntityType entity_type = EntityType::Unknown; ///< Polymer, NonPolymer, Water, or Unknown
  char het_flag = '\0';   ///< 'A' = ATOM record, 'H' = HETATM record, '\0' = unspecified
  char flag = '\0';       ///< Custom flag for user-defined marking
  ResidueSs ss_from_file = ResidueSs::Coil;    ///< Secondary structure from structure file
  ResidueStrandSense strand_sense_from_file = ResidueStrandSense::NotStrand; ///< Strand sense in sheet
  SiftsUnpResidue sifts_unp;  ///< UniProt reference from SIFTS mapping
  short group_idx = 0;        ///< Internal variable (ignore)
  std::vector<Atom> atoms;    ///< List of atoms in this residue

  Residue() = default;
  /// @brief Construct residue from a ResidueId (number and insertion code).
  explicit Residue(const ResidueId& rid) noexcept : ResidueId(rid) {}

  /// @brief Create a shallow copy of all fields except atoms (children).
  /// Used in template code for hierarchical copying.
  /// @return New Residue with metadata copied but empty atoms vector
  Residue empty_copy() const {
    Residue res((ResidueId&)*this);
    res.subchain = subchain;
    res.entity_id = entity_id;
    res.label_seq = label_seq;
    res.entity_type = entity_type;
    res.het_flag = het_flag;
    res.flag = flag;
    res.ss_from_file = ss_from_file;
    res.strand_sense_from_file = strand_sense_from_file;
    res.sifts_unp = sifts_unp;
    return res;
  }

  using child_type = Atom;
  /// @brief Access mutable atoms vector.
  std::vector<Atom>& children() { return atoms; }
  /// @brief Access const atoms vector.
  const std::vector<Atom>& children() const { return atoms; }

  /// @brief Find first atom with given element.
  /// @param el Element to search for
  /// @return Pointer to atom, or nullptr if not found
  const Atom* find_by_element(El el) const {
    for (const Atom& a : atoms)
      if (a.element == el)
        return &a;
    return nullptr;
  }

  /// @brief Find atom by name, alternate location, and optional element.
  /// In strict_altloc mode (default), '*' matches any altloc, '\0' matches atoms without altloc.
  /// When strict_altloc is false, '\0' is treated as a wildcard match (same as '*').
  /// @param atom_name Name of atom to find (e.g., "CA", "CB")
  /// @param altloc Alternate location character ('*' = any, '\0' = none)
  /// @param el Element to match (El::X = any element, default)
  /// @param strict_altloc If true, use PDB conventions for altloc matching; if false, '\0' is wildcard
  /// @return Pointer to matching atom, or nullptr if not found
  Atom* find_atom(const std::string& atom_name, char altloc, El el=El::X,
                  bool strict_altloc=true) {
    if (!strict_altloc && altloc == '\0')
      altloc = '*';
    for (Atom& a : atoms)
      if (a.name == atom_name && a.altloc_matches(altloc) && (el == El::X || a.element == el))
        return &a;
    return nullptr;
  }
  /// @copydoc find_atom(const std::string&, char, El, bool)
  const Atom* find_atom(const std::string& atom_name, char altloc, El el=El::X,
                        bool strict_altloc=true) const {
    return const_cast<Residue*>(this)->find_atom(atom_name, altloc, el, strict_altloc);
  }

  /// @brief Find iterator to atom by name, alternate location, and optional element.
  /// @param atom_name Name of atom to find
  /// @param altloc Alternate location character
  /// @param el Element to match (El::X = any, default)
  /// @return Iterator to the atom
  /// @throws fail() if atom not found
  std::vector<Atom>::iterator find_atom_iter(const std::string& atom_name,
                                             char altloc, El el=El::X) {
    if (Atom* a = find_atom(atom_name, altloc, el))
      return atoms.begin() + (a - atoms.data());
    fail("Atom not found.");
  }

  /// @brief Get group of atoms with the same name (different alternate locations).
  /// @param atom_name Name of atoms to group
  /// @return AtomGroup containing all atoms with this name
  /// @throws fail() if no atoms with this name exist
  AtomGroup get(const std::string& atom_name) {
    for (Atom& atom : atoms)
      if (atom.name == atom_name)
        return AtomGroup(&atom, atoms.data() + atoms.size());
    fail("No such atom: " + atom_name);
  }

  /// @brief Get the single atom with given name.
  /// Fails if there are multiple alternate conformations.
  /// @param atom_name Name of atom to find
  /// @return Reference to the unique atom
  /// @throws fail() if atom not found or multiple alternative atoms exist
  Atom& sole_atom(const std::string& atom_name) {
    AtomGroup aa = get(atom_name);
    if (aa.size() != 1)
      fail("Multiple alternative atoms " + atom_name);
    return aa.front();
  }

  /// @brief Find peptide backbone CA (alpha carbon) atom.
  /// @return Pointer to CA atom, or nullptr
  const Atom* get_ca() const { return find_atom("CA", '*', El::C); }
  /// @brief Find peptide backbone C (carbonyl carbon) atom.
  /// @return Pointer to C atom, or nullptr
  const Atom* get_c() const { return find_atom("C", '*', El::C); }
  /// @brief Find peptide backbone N (amide nitrogen) atom.
  /// @return Pointer to N atom, or nullptr
  const Atom* get_n() const { return find_atom("N", '*', El::N); }
  /// @brief Find peptide backbone O (carbonyl oxygen) atom.
  /// @return Pointer to O atom, or nullptr
  const Atom* get_o() const { return find_atom("O", '*', El::O); }
  /// @brief Find nucleic acid phosphorus atom.
  /// @return Pointer to P atom, or nullptr
  const Atom* get_p() const { return find_atom("P", '*', El::P); }
  /// @brief Find nucleic acid O3' (3-prime oxygen) atom.
  /// @return Pointer to O3' atom, or nullptr
  const Atom* get_o3prim() const { return find_atom("O3'", '*', El::O); }

  /// @brief Check if this residue belongs to the same conformer as another.
  /// Compatible if either has no alternate locations, or they share an altloc.
  /// @param other The other residue to compare
  /// @return true if residues are in the same conformer
  bool same_conformer(const Residue& other) const {
    return atoms.empty() || other.atoms.empty() ||
           atoms[0].same_conformer(other.atoms[0]) ||
           other.find_atom(other.atoms[0].name, atoms[0].altloc) != nullptr;
  }

  /// @brief Check if this residue is a water molecule.
  /// Recognizes HOH, DOD (deuterated water), WAT, H2O.
  /// Does not match OH or H3O/D3O.
  /// @return true if residue name matches water identifiers
  bool is_water() const {
    if (name.length() != 3)
      return false;
    int id = ialpha4_id(name.c_str());
    return id == ialpha4_id("HOH") || id == ialpha4_id("DOD") ||
           id == ialpha4_id("WAT") || id == ialpha4_id("H2O");
  }

  /// @brief Get proxy for iterating over atoms of the first conformer only.
  /// Useful for skipping alternate conformations in loops.
  /// @return Iterator proxy that yields only the first alternate location
  UniqProxy<Atom> first_conformer() { return {atoms}; }
  /// @copydoc first_conformer()
  ConstUniqProxy<Atom> first_conformer() const { return {atoms}; }
};

/// @brief Collect all distinct alternate location characters from a residue.
/// Appends unique altloc characters to the provided string.
/// @param res The residue to scan
/// @param altlocs String to accumulate altloc characters (not cleared first)
inline void add_distinct_altlocs(const Residue& res, std::string& altlocs) {
  for (const Atom& atom : res.atoms)
    if (atom.altloc && altlocs.find(atom.altloc) == std::string::npos)
      altlocs += atom.altloc;
}

struct ResidueGroup;
struct ConstResidueGroup;

/// @brief Immutable span of residues within a Chain.
///
/// Represents a contiguous sequence of residues with utility methods
/// for manipulation, grouping, and sequence numbering conversions.
struct ConstResidueSpan : Span<const Residue> {
  using Parent = Span<const Residue>;
  using Parent::Span;
  /// @brief Construct from a moved span.
  ConstResidueSpan(Parent&& span) : Parent(std::move(span)) {}

  /// @brief Count unique residues, accounting for microheterogeneity.
  /// Residues with the same sequence number but different names count as one.
  /// @return Number of unique sequence positions
  int length() const {
    int length = (int) size();
    for (int n = length - 1; n > 0; --n)
      if ((begin() + n)->group_key() == (begin() + n - 1)->group_key())
        --length;
    return length;
  }

  /// @brief Find extreme (minimum or maximum) sequence number in span.
  /// @param label If true, use label_seq_id; if false, use seqid
  /// @param sign -1 for minimum, +1 for maximum
  /// @return The extreme sequence number, or unset if span is empty
  SeqId::OptionalNum extreme_num(bool label, int sign) const {
    SeqId::OptionalNum result;
    for (const Residue& r : *this) {
      if (auto num = label ? r.label_seq : r.seqid.num)
        if (!result || sign * int(num) > sign * int(result))
          result = num;
    }
    return result;
  }

  /// @brief Get proxy for iterating over the first conformer only.
  /// Skips alternate conformations (microheterogeneity).
  /// @return Iterator proxy
  ConstUniqProxy<Residue, ConstResidueSpan> first_conformer() const {
    return {*this};
  }

  /// @brief Get the subchain identifier common to all residues in span.
  /// @return The subchain ID
  /// @throws std::out_of_range if span is empty
  /// @throws fail() if residues have different subchain IDs
  const std::string& subchain_id() const {
    if (this->empty())
      throw std::out_of_range("subchain_id(): empty span");
    if (this->size() > 1 && this->front().subchain != this->back().subchain)
      fail("subchain id varies in a residue span: ", this->front().subchain,
           " vs ", this->back().subchain);
    return this->begin()->subchain;
  }

  /// @brief Find residue group with given sequence ID.
  /// @param id Sequence ID to search for
  /// @return ConstResidueGroup containing residues with this sequence ID
  ConstResidueGroup find_residue_group(SeqId id) const;

  /// @brief Extract sequence of residue names from first conformer.
  /// @return Vector of residue names (one per unique sequence position)
  std::vector<std::string> extract_sequence() const {
    std::vector<std::string> seq;
    for (const Residue& res : first_conformer())
      seq.push_back(res.name);
    return seq;
  }

  /// @brief Convert from canonical sequence number to author (auth) sequence ID.
  /// Assumes residues are ordered; works approximately with missing numbers.
  /// @param label_seq_id Canonical sequence number to convert
  /// @return Author sequence ID as a SeqId (number + insertion code)
  /// @throws std::out_of_range if span is empty
  SeqId label_seq_id_to_auth(SeqId::OptionalNum label_seq_id) const {
    if (empty())
      throw std::out_of_range("label_seq_id_to_auth(): empty span");
    const auto* it = std::lower_bound(begin(), end(), label_seq_id,
        [](const Residue& r, SeqId::OptionalNum v){ return r.label_seq < v; });
    if (it == end())
      --it;
    else if (it->label_seq == label_seq_id)
      return it->seqid;
    else if (it != begin() &&
             label_seq_id - (it-1)->label_seq < it->label_seq - label_seq_id)
      --it;
    return {it->seqid.num + (label_seq_id - it->label_seq), ' '};
  }

  /// @brief Convert from author (auth) sequence ID to canonical sequence number.
  /// Uses a heuristic since author residue numbers are sometimes not ordered.
  /// @param auth_seq_id Author sequence ID to convert
  /// @return Canonical sequence number
  /// @throws std::out_of_range if span is empty
  SeqId::OptionalNum auth_seq_id_to_label(SeqId auth_seq_id) const {
    if (empty())
      throw std::out_of_range("auth_seq_id_to_label(): empty span");
    for (const Residue& r : *this)
      if (r.seqid == auth_seq_id)
        return r.label_seq;
    const_iterator it;
    if (auth_seq_id.num < front().seqid.num) {
      it = begin();
    } else if (back().seqid.num < auth_seq_id.num) {
      it = end() - 1;
    } else {
      it = std::lower_bound(begin(), end(), auth_seq_id.num,
        [](const Residue& r, SeqId::OptionalNum v){ return r.seqid.num < v; });
      while (it != end() && it->seqid.num == auth_seq_id.num &&
             it->seqid.icode != auth_seq_id.icode)
        ++it;
      if (it == end())
        --it;
    }
    return it->label_seq + (auth_seq_id.num - it->seqid.num);
  }
};

/// @brief Mutable span of consecutive residues within a chain.
/// Represents a contiguous subsequence of residues that can be modified.
/// It is returned by get_polymer(), get_ligands(), get_waters() and get_subchain().
struct ResidueSpan : MutableVectorSpan<Residue> {
  using Parent = MutableVectorSpan<Residue>;
  struct GroupingProxy;
  ResidueSpan() = default;
  /// @brief Construct from a moved span.
  ResidueSpan(Parent&& span) : Parent(std::move(span)) {}
  /// @brief Construct from a vector with specific range.
  ResidueSpan(vector_type& v, iterator begin, std::size_t n)
    : Parent(v, begin, n) {}
  /// @copydoc ConstResidueSpan::length()
  int length() const { return const_().length(); }
  /// @copydoc ConstResidueSpan::extreme_num()
  SeqId::OptionalNum extreme_num(bool label, int sign) const {
    return const_().extreme_num(label, sign);
  }
  /// @copydoc ConstResidueSpan::first_conformer()
  UniqProxy<Residue, ResidueSpan> first_conformer() { return {*this}; }
  /// @copydoc ConstResidueSpan::first_conformer()
  ConstUniqProxy<Residue, ResidueSpan> first_conformer() const { return {*this}; }
  /// @brief Get proxy for iterating over residue groups (microheterogeneity-aware).
  GroupingProxy residue_groups();
  /// @copydoc ConstResidueSpan::subchain_id()
  const std::string& subchain_id() const { return const_().subchain_id(); }
  /// @brief Find residue group with given sequence ID.
  /// @param id Sequence ID to search for
  /// @return ResidueGroup containing residues with this sequence ID
  ResidueGroup find_residue_group(SeqId id);
  /// @copydoc ConstResidueSpan::extract_sequence()
  std::vector<std::string> extract_sequence() const { return const_().extract_sequence(); }
  /// @copydoc ConstResidueSpan::find_residue_group()
  ConstResidueGroup find_residue_group(SeqId id) const;
  /// @copydoc ConstResidueSpan::label_seq_id_to_auth()
  SeqId label_seq_id_to_auth(SeqId::OptionalNum label_seq_id) const {
    return const_().label_seq_id_to_auth(label_seq_id);
  }
  /// @copydoc ConstResidueSpan::auth_seq_id_to_label()
  SeqId::OptionalNum auth_seq_id_to_label(SeqId auth_seq_id) const {
    return const_().auth_seq_id_to_label(auth_seq_id);
  }
private:
  ConstResidueSpan const_() const { return ConstResidueSpan(begin(), size()); }
};

/// @brief Group of residues with the same sequence ID but different names.
/// Represents microheterogeneity (multiple forms of the same residue position).
/// Usually contains only one residue; multiple residues indicate alternate conformations.
/// Residues within a group must be consecutive.
struct ResidueGroup : ResidueSpan {
  ResidueGroup() = default;
  /// @brief Construct from a moved span.
  ResidueGroup(ResidueSpan&& span) : ResidueSpan(std::move(span)) {}
  /// @brief Find residue in group by residue name.
  /// @param name Residue name to search for (e.g., "ALA", "GLY")
  /// @return Reference to residue with this name
  /// @throws fail() if no residue with this name found
  Residue& by_resname(const std::string& name) {
    return *impl::find_iter(*this, name);
  }
  /// @brief Remove residue from group by name.
  /// @param name Residue name to remove
  void remove_residue(const std::string& name) {
    erase(impl::find_iter(*this, name));
  }
};

/// @brief Const version of ResidueGroup.
struct ConstResidueGroup : ConstResidueSpan {
  ConstResidueGroup() = default;
  /// @brief Construct from a moved span.
  ConstResidueGroup(ConstResidueSpan&& sp) : ConstResidueSpan(std::move(sp)) {}
  /// @brief Find residue in group by residue name.
  /// @param name Residue name to search for
  /// @return Const reference to residue with this name
  /// @throws fail() if no residue with this name found
  const Residue& by_resname(const std::string& name) {
    return *impl::find_iter(*this, name);
  }
};

inline ResidueGroup ResidueSpan::find_residue_group(SeqId id) {
  return ResidueSpan(subspan([&](const Residue& r) { return r.seqid == id; }));
}
inline ConstResidueGroup ResidueSpan::find_residue_group(SeqId id) const {
  return const_().find_residue_group(id);
}
inline ConstResidueGroup ConstResidueSpan::find_residue_group(SeqId id) const {
  return ConstResidueSpan(subspan([&](const Residue& r) { return r.seqid == id; }));
}

/// @brief Proxy providing iteration over ResidueGroups within a ResidueSpan.
///
/// Each ResidueGroup contains residues with the same sequence number
/// (microheterogeneities — point mutations stored as alternative residues).
struct ResidueSpan::GroupingProxy {
  ResidueSpan& span;
  using iterator = GroupingIter<ResidueSpan, ResidueGroup>;
  /// @brief Get iterator to first residue group.
  iterator begin() {
    return ++iterator{ResidueGroup(span.sub(span.begin(), span.begin()))};
  }
  /// @brief Get iterator past last residue group.
  iterator end() {
    return iterator{ResidueGroup(span.sub(span.end(), span.end()))};
  }
};

/// @copydoc ResidueSpan::residue_groups()
inline ResidueSpan::GroupingProxy ResidueSpan::residue_groups() {
  return {*this};
}


namespace impl {
template<typename T, typename Ch> std::vector<T> chain_subchains(Ch* ch) {
  std::vector<T> v;
  for (auto start = ch->residues.begin(); start != ch->residues.end(); ) {
    auto end = start + 1;
    while (end != ch->residues.end() && end->subchain == start->subchain)
      ++end;
    v.push_back(ch->whole().sub(start, end));
    start = end;
  }
  return v;
}
} // namespace impl

/// @brief Represents a chain of residues (typically named A, B, C, ...).
/// A chain is a sequence of residues, often corresponding to a polypeptide or polynucleotide.
struct Chain {
  static const char* what() { return "Chain"; }
  std::string name;              ///< Chain identifier (usually single letter)
  std::vector<Residue> residues; ///< Residues in this chain

  Chain() = default;
  /// @brief Construct chain with a given name.
  explicit Chain(const std::string& name_) noexcept : name(name_) {}

  /// @brief Get span covering all residues in chain.
  /// @return Mutable residue span for entire chain
  ResidueSpan whole() {
    Residue* begin = residues.empty() ? nullptr : &residues[0];
    return ResidueSpan(residues, begin, residues.size());
  }
  /// @copydoc whole()
  ConstResidueSpan whole() const {
    const Residue* begin = residues.empty() ? nullptr : &residues[0];
    return ConstResidueSpan(begin, residues.size());
  }

  /// @brief Get residue span matching a predicate function.
  /// @tparam F Callable taking const Residue& and returning bool
  /// @param func Predicate function
  /// @return Mutable span of matching residues
  template<typename F> ResidueSpan get_residue_span(F&& func) {
    return whole().subspan(func);
  }
  /// @copydoc get_residue_span()
  template<typename F> ConstResidueSpan get_residue_span(F&& func) const {
    return whole().subspan(func);
  }

  /// @brief Get span of polymer residues in this chain.
  /// Finds the first contiguous span of polymer residues in the same subchain.
  /// @return Mutable span of polymer residues, or empty if none found
  ResidueSpan get_polymer() {
    auto begin = residues.begin();
    while (begin != residues.end() && begin->entity_type != EntityType::Polymer)
      ++begin;
    auto end = begin;
    while (end != residues.end() && end->entity_type == EntityType::Polymer
                                 && end->subchain == begin->subchain)
      ++end;
    return ResidueSpan(residues, &*begin, end - begin);
  }
  /// @copydoc get_polymer()
  ConstResidueSpan get_polymer() const {
    return const_cast<Chain*>(this)->get_polymer();
  }

  /// @brief Get span of ligand residues (NonPolymer or Branched entities).
  /// @return Mutable span of ligand residues
  ResidueSpan get_ligands() {
    return get_residue_span([](const Residue& r) {
        return r.entity_type == EntityType::NonPolymer ||
               r.entity_type == EntityType::Branched;
    });
  }
  /// @copydoc get_ligands()
  ConstResidueSpan get_ligands() const {
    return const_cast<Chain*>(this)->get_ligands();
  }

  /// @brief Get span of water residues.
  /// @return Mutable span of water molecules
  ResidueSpan get_waters() {
    return get_residue_span([](const Residue& r) {
        return r.entity_type == EntityType::Water;
    });
  }
  /// @copydoc get_waters()
  ConstResidueSpan get_waters() const {
    return const_cast<Chain*>(this)->get_waters();
  }

  /// @brief Get span of residues with given subchain identifier.
  /// @param s Subchain ID to search for
  /// @return Mutable span of matching residues
  ResidueSpan get_subchain(const std::string& s) {
    return get_residue_span([&](const Residue& r) { return r.subchain == s; });
  }
  /// @copydoc get_subchain()
  ConstResidueSpan get_subchain(const std::string& s) const {
    return const_cast<Chain*>(this)->get_subchain(s);
  }

  /// @brief Get list of subchain spans (grouped by subchain identifier).
  /// Each subchain is a contiguous sequence of residues with the same subchain ID.
  /// @return Vector of mutable residue spans, one per subchain
  std::vector<ResidueSpan> subchains() {
    return impl::chain_subchains<ResidueSpan>(this);
  }
  /// @copydoc subchains()
  std::vector<ConstResidueSpan> subchains() const {
    return impl::chain_subchains<ConstResidueSpan>(this);
  }

  /// @brief Find residue group with given sequence ID.
  /// @param id Sequence ID to search for
  /// @return ResidueGroup containing residues with this sequence ID
  ResidueGroup find_residue_group(SeqId id) {
    return whole().find_residue_group(id);
  }
  /// @copydoc find_residue_group()
  ConstResidueGroup find_residue_group(SeqId id) const {
    return whole().find_residue_group(id);
  }

  /// @brief Find residue by ResidueId (number and insertion code).
  /// @param rid ResidueId to search for
  /// @return Pointer to matching residue, or nullptr if not found
  Residue* find_residue(const ResidueId& rid);
  /// @copydoc find_residue()
  const Residue* find_residue(const ResidueId& rid) const {
    return const_cast<Chain*>(this)->find_residue(rid);
  }

  /// @brief Find residue by ResidueId, or create it if not found.
  /// @param rid ResidueId to search for or create
  /// @return Reference to existing or newly created residue
  Residue* find_or_add_residue(const ResidueId& rid);

  /// @brief Append residues to this chain with optional minimum separation.
  /// Adjusts sequence numbers if needed to maintain minimum separation.
  /// @param new_resi Vector of residues to append
  /// @param min_sep Minimum sequence number separation (0 = no enforcement)
  void append_residues(std::vector<Residue> new_resi, int min_sep=0);

  /// @brief Create a shallow copy with same name but empty residues.
  /// Used in template code for hierarchical copying.
  Chain empty_copy() const { return Chain(name); }

  using child_type = Residue;
  /// @brief Access mutable residues vector.
  std::vector<Residue>& children() { return residues; }
  /// @brief Access const residues vector.
  const std::vector<Residue>& children() const { return residues; }

  /// @brief Check if residue is the first in its group (sequence number).
  /// Returns false only for alternative conformations (microheterogeneity).
  /// @param res The residue to check
  /// @return true if res is the first residue with its sequence number
  bool is_first_in_group(const Residue& res) const {
    return &res == residues.data() || (&res - 1)->group_key() != res.group_key();
  }

  /// @brief Get the previous different sequence number residue.
  /// Handles microheterogeneity and alternate conformations correctly.
  /// @param res The reference residue
  /// @return Pointer to previous residue (by sequence number), or nullptr if none
  const Residue* previous_residue(const Residue& res) const {
    const Residue* start = residues.data();
    for (const Residue* p = &res; p-- != start; )
      if (res.group_key() != p->group_key()) {
        while (p != start && p->group_key() == (p-1)->group_key() &&
               (res.atoms.at(0).altloc == '\0' || !res.same_conformer(*p)))
          --p;
        return p;
      }
    return nullptr;
  }

  /// @brief Get the next different sequence number residue.
  /// Handles microheterogeneity and alternate conformations correctly.
  /// @param res The reference residue
  /// @return Pointer to next residue (by sequence number), or nullptr if none
  const Residue* next_residue(const Residue& res) const {
    const Residue* end = residues.data() + residues.size();
    for (const Residue* p = &res + 1; p != end; ++p)
      if (res.group_key() != p->group_key()) {
        while (p+1 != end && p->group_key() == (p+1)->group_key() &&
               !res.same_conformer(*p))
          ++p;
        return p;
      }
    return nullptr;
  }

  /// @brief Get proxy for iterating over first conformer only.
  /// Skips alternate conformations (microheterogeneity).
  /// @return Iterator proxy
  UniqProxy<Residue> first_conformer() { return {residues}; }
  /// @copydoc first_conformer()
  ConstUniqProxy<Residue> first_conformer() const { return {residues}; }
};

/// @brief Convert Chain, ResidueId, and Atom to a string representation.
/// @param chain The chain
/// @param res_id The residue ID
/// @param atom The atom
/// @param as_cid If true, format as CIF; if false, format as PDB
/// @return String representation of the atom location
inline std::string atom_str(const Chain& chain,
                            const ResidueId& res_id,
                            const Atom& atom,
                            bool as_cid=false) {
  return atom_str(chain.name, res_id, atom.name, atom.altloc, as_cid);
}

/// @brief Const pointer triple: Chain, Residue, Atom.
/// Used for read-only access to structure hierarchy.
struct const_CRA {
  const Chain* chain;     ///< Pointer to chain, or nullptr
  const Residue* residue; ///< Pointer to residue, or nullptr
  const Atom* atom;       ///< Pointer to atom, or nullptr
};

/// @brief Mutable pointer triple: Chain, Residue, Atom.
/// Used for modifiable access to structure hierarchy.
struct CRA {
  Chain* chain;     ///< Pointer to chain, or nullptr
  Residue* residue; ///< Pointer to residue, or nullptr
  Atom* atom;       ///< Pointer to atom, or nullptr
  /// @brief Implicit conversion to const version.
  operator const_CRA() const { return const_CRA{chain, residue, atom}; }
};

/// @brief Convert const_CRA (Chain, Residue, Atom pointers) to string.
/// Handles null pointers gracefully.
/// @param cra Chain-Residue-Atom triple
/// @param as_cif If true, format as CIF; if false, format as PDB
/// @return String representation of the atom location
inline std::string atom_str(const const_CRA& cra, bool as_cif=false) {
  static const ResidueId null_residue_id = {};
  return atom_str(cra.chain ? cra.chain->name : "null",
                  cra.residue ? *cra.residue : null_residue_id,
                  cra.atom ? cra.atom->name : "null",
                  cra.atom ? cra.atom->altloc : '\0',
                  as_cif);
}

/// @brief Check if a const_CRA matches an AtomAddress specification.
/// @param cra Chain-Residue-Atom triple to test
/// @param addr Target atom address
/// @param ignore_segment If true, don't check segment ID
/// @return true if all relevant fields match
inline bool atom_matches(const const_CRA& cra, const AtomAddress& addr, bool ignore_segment=false) {
  return cra.chain && cra.chain->name == addr.chain_name &&
         cra.residue && cra.residue->matches_noseg(addr.res_id) &&
         (ignore_segment || cra.residue->segment == addr.res_id.segment) &&
         cra.atom && cra.atom->name == addr.atom_name &&
         cra.atom->altloc == addr.altloc;
}

/// @brief Create an AtomAddress from Chain, Residue, and Atom.
/// @param ch The chain
/// @param res The residue
/// @param at The atom
/// @return AtomAddress specifying this atom
inline AtomAddress make_address(const Chain& ch, const Residue& res, const Atom& at) {
  return AtomAddress(ch.name, res, at.name, at.altloc);
}


/// @brief Iterator policy for traversing Chain/Residue/Atom (CRA) triples.
///
/// Used with Gemmi's generic iterator framework to provide bidirectional
/// iteration over all atoms in a Model, yielding CRA structs.
/// @tparam CraT Either `CRA` (mutable) or `const_CRA` (immutable).
template<typename CraT>
class CraIterPolicy {
public:
  using value_type = CraT;
  using reference = const CraT;
  /// @brief Construct empty iterator.
  CraIterPolicy() : chains_end(nullptr), cra{nullptr, nullptr, nullptr} {}
  /// @brief Construct iterator at specific position.
  /// @param end Pointer to end of chains array
  /// @param cra_ Initial Chain-Residue-Atom triple
  CraIterPolicy(const Chain* end, CraT cra_) : chains_end(end), cra(cra_) {}

  /// @brief Advance to next atom.
  void increment() {
    if (cra.atom == nullptr)
      return;
    if (++cra.atom == vector_end_ptr(cra.residue->atoms)) {
      do {
        if (++cra.residue == vector_end_ptr(cra.chain->residues)) {
          do {
            if (++cra.chain == chains_end) {
              cra.atom = nullptr;
              return;
            }
          } while (cra.chain->residues.empty());
          cra.residue = &cra.chain->residues[0];
        }
      } while (cra.residue->atoms.empty());
      cra.atom = &cra.residue->atoms[0];
    }
  }

  /// @brief Advance to previous atom.
  void decrement() {
    while (cra.atom == nullptr || cra.atom == cra.residue->atoms.data()) {
      while (cra.residue == nullptr || cra.residue == cra.chain->residues.data()) {
        // iterating backward beyond begin() will have undefined effects
        while ((--cra.chain)->residues.empty()) {}
        cra.residue = vector_end_ptr(cra.chain->residues);
      }
      --cra.residue;
      cra.atom = vector_end_ptr(cra.residue->atoms);
    }
    --cra.atom;
  }

  /// @brief Check equality with another policy.
  bool equal(const CraIterPolicy& o) const { return cra.atom == o.cra.atom; }

  /// @brief Get current Chain-Residue-Atom triple.
  CraT dereference() { return cra; }  // make copy b/c increment() modifies cra

  using const_policy = CraIterPolicy<const_CRA>;
  /// @brief Implicit conversion to const policy.
  operator const_policy() const { return const_policy(chains_end, cra); }

private:
  const Chain* chains_end;
  CraT cra;
};

/// @brief Proxy object for iterating over Chain/Residue/Atom triples in a Model.
///
/// Provides begin()/end() to enable range-for iteration over all CRA entries.
/// @tparam CraT Either `CRA` (mutable) or `const_CRA` (immutable).
/// @tparam ChainsRefT Reference to chains vector (mutable or const)
template<typename CraT, typename ChainsRefT>
struct CraProxy_ {
  ChainsRefT chains;    ///< Reference to chains vector
  using iterator = BidirIterator<CraIterPolicy<CraT>>;

  /// @brief Get iterator to first atom in structure.
  iterator begin() {
    for (auto& chain : chains)
      for (auto& residue : chain.residues)
        for (auto& atom : residue.atoms)
          return CraIterPolicy<CraT>{vector_end_ptr(chains), CraT{&chain, &residue, &atom}};
    return {};
  }

  /// @brief Get iterator past last atom in structure.
  iterator end() {
    auto* chains_end = vector_end_ptr(chains);
    return CraIterPolicy<CraT>{chains_end, CraT{chains_end, nullptr, nullptr}};
  }
};

using CraProxy = CraProxy_<CRA, std::vector<Chain>&>;           ///< Mutable all-atoms proxy
using ConstCraProxy = CraProxy_<const_CRA, const std::vector<Chain>&>; ///< Const all-atoms proxy

/// @brief Represents a single model in an NMR ensemble or multi-model structure.
/// Each model contains a set of chains with complete atomic coordinates.
struct Model {
  static const char* what() { return "Model"; }
  int num = 0;                ///< Model number (usually 1-based)
  std::vector<Chain> chains;   ///< Chains in this model

  Model() = default;
  /// @brief Construct model with given number.
  /// @param num_ Model number to assign
  explicit Model(int num_) noexcept : num(num_) {}

  /// @brief Find first chain with given name.
  /// @param chain_name Name of chain to search for
  /// @return Pointer to chain, or nullptr if not found
  Chain* find_chain(const std::string& chain_name) {
    return impl::find_or_null(chains, chain_name);
  }
  /// @copydoc find_chain()
  const Chain* find_chain(const std::string& chain_name) const {
    return const_cast<Model*>(this)->find_chain(chain_name);
  }

  /// @brief Find last chain with given name.
  /// Useful when the same chain name appears multiple times.
  /// @param chain_name Name of chain to search for
  /// @return Pointer to last matching chain, or nullptr if not found
  Chain* find_last_chain(const std::string& chain_name) {
    auto it = std::find_if(chains.rbegin(), chains.rend(),
                         [&](const Chain& c) { return c.name == chain_name; });
    return it != chains.rend() ? &*it : nullptr;
  }

  /// @brief Remove all chains with given name.
  /// @param chain_name Name of chains to remove
  void remove_chain(const std::string& chain_name) {
    vector_remove_if(chains,
                     [&](const Chain& c) { return c.name == chain_name; });
  }

  /// @brief Merge consecutive chains with the same name.
  /// Appends residues from later chains to earlier ones with matching names.
  /// @param min_sep Minimum sequence number separation between merged chains (0 = no enforcement)
  void merge_chain_parts(int min_sep=0) {
    for (auto i = chains.begin(); i != chains.end(); ++i)
      for (auto j = i + 1; j != chains.end(); ++j)
        if (i->name == j->name) {
          i->append_residues(j->residues, min_sep);
          chains.erase(j--);
        }
  }

  /// @brief Get residue span with given subchain identifier.
  /// @param sub_name Subchain ID to search for
  /// @return ResidueSpan of matching residues, or empty span if not found
  ResidueSpan get_subchain(const std::string& sub_name) {
    for (Chain& chain : chains)
      if (ResidueSpan sub = chain.get_subchain(sub_name))
        return sub;
    return ResidueSpan();
  }
  /// @copydoc get_subchain()
  ConstResidueSpan get_subchain(const std::string& sub_name) const {
    return const_cast<Model*>(this)->get_subchain(sub_name);
  }

  /// @brief Get list of all subchains in all chains.
  /// @return Vector of mutable residue spans, one per subchain
  std::vector<ResidueSpan> subchains() {
    return impl::model_subchains<ResidueSpan>(this);
  }
  /// @copydoc subchains()
  std::vector<ConstResidueSpan> subchains() const {
    return impl::model_subchains<ConstResidueSpan>(this);
  }

  /// @brief Create mapping from subchain IDs to chain names.
  /// @return Map: subchain_id -> chain_name
  std::map<std::string, std::string> subchain_to_chain() const {
    std::map<std::string, std::string> mapping;
    for (const Chain& chain : chains) {
      std::string prev;
      for (const Residue& res : chain.residues)
        if (!res.subchain.empty() && res.subchain != prev) {
          prev = res.subchain;
          mapping[res.subchain] = chain.name;
        }
    }
    return mapping;
  }

  /// @brief Find residue in a specific chain by ResidueId.
  /// @param chain_name Name of chain to search in
  /// @param rid ResidueId (number and insertion code) to search for
  /// @return Pointer to residue, or nullptr if not found
  Residue* find_residue(const std::string& chain_name, const ResidueId& rid) {
    for (Chain& chain : chains)
      if (chain.name == chain_name)
        if (Residue* residue = chain.find_residue(rid))
          return residue;
    return nullptr;
  }
  /// @copydoc find_residue()
  const Residue* find_residue(const std::string& chain_name, const ResidueId& rid) const {
    return const_cast<Model*>(this)->find_residue(chain_name, rid);
  }

  /// @brief Find residue group (microheterogeneity-aware) in specific chain.
  /// @param chain_name Name of chain to search in
  /// @param seqid Sequence ID to search for
  /// @return ResidueGroup containing residues with this sequence ID
  /// @throws fail() if chain or residue not found
  ResidueGroup find_residue_group(const std::string& chain_name, SeqId seqid) {
    for (Chain& chain : chains)
      if (chain.name == chain_name)
        if (ResidueGroup res_group = chain.find_residue_group(seqid))
          return res_group;
    fail("No such chain or residue: " + chain_name + " " + seqid.str());
  }

  /// @brief Find single residue in specific chain by sequence ID.
  /// Fails if there are multiple residues at this position (microheterogeneity).
  /// @param chain_name Name of chain to search in
  /// @param seqid Sequence ID to search for
  /// @return Reference to the unique residue
  /// @throws fail() if residue not found or multiple alternatives exist
  Residue& sole_residue(const std::string& chain_name, SeqId seqid) {
    ResidueSpan rr = find_residue_group(chain_name, seqid);
    if (rr.size() != 1)
      fail("Multiple residues " + chain_name + " " + seqid.str());
    return rr[0];
  }

  /// @brief Get list of all unique residue names in model.
  /// @return Vector of residue names (e.g., "ALA", "GLY", "HOH")
  std::vector<std::string> get_all_residue_names() const {
    std::vector<std::string> names;
    for (const Chain& chain : chains)
      for (const Residue& res : chain.residues)
        if (!in_vector(res.name, names))
          names.push_back(res.name);
    return names;
  }

  /// @brief Find atom by AtomAddress specification.
  /// @param address AtomAddress specifying chain, residue, and atom
  /// @param ignore_segment If true, ignore segment ID in matching
  /// @return Chain-Residue-Atom triple (pointers may be null if not found)
  CRA find_cra(const AtomAddress& address, bool ignore_segment=false) {
    for (Chain& chain : chains)
      if (chain.name == address.chain_name) {
        for (Residue& res : chain.residues)
          if (address.res_id.matches_noseg(res) &&
              (ignore_segment || address.res_id.segment == res.segment)) {
            Atom *at = nullptr;
            if (!address.atom_name.empty())
              at = res.find_atom(address.atom_name, address.altloc);
            return {&chain, &res, at};
          }
      }
    return {nullptr, nullptr, nullptr};
  }

  /// @copydoc find_cra()
  const_CRA find_cra(const AtomAddress& address, bool ignore_segment=false) const {
    return const_cast<Model*>(this)->find_cra(address, ignore_segment);
  }

  /// @brief Get proxy for iterating over all atoms in model.
  /// @return Mutable proxy over all Chain-Residue-Atom triples
  CraProxy all() { return {chains}; }
  /// @copydoc all()
  ConstCraProxy all() const { return {chains}; }

  /// @brief Find atom by AtomAddress.
  /// @param address AtomAddress specifying the atom
  /// @return Pointer to atom, or nullptr if not found
  Atom* find_atom(const AtomAddress& address) { return find_cra(address).atom; }
  /// @copydoc find_atom()
  const Atom* find_atom(const AtomAddress& address) const { return find_cra(address).atom; }

  /// @brief Get array indices of chain, residue, and atom in model.
  /// Returns -1 for any pointer that is nullptr.
  /// @param c Pointer to chain (may be null)
  /// @param r Pointer to residue (may be null)
  /// @param a Pointer to atom (may be null)
  /// @return Array of 3 indices: [chain_index, residue_index, atom_index]
  std::array<int, 3> get_indices(const Chain* c, const Residue* r,
                                 const Atom* a) const {
    return {{ c      ? static_cast<int>(c - chains.data()) : -1,
              c && r ? static_cast<int>(r - c->residues.data()) : -1,
              r && a ? static_cast<int>(a - r->atoms.data()) : -1 }};
  }

  /// @brief Get a bitset of all elements present in model.
  /// @return Bitset with one bit per Element type
  std::bitset<(size_t)El::END> present_elements() const {
    std::bitset<(size_t)El::END> table;
    for (const Chain& chain : chains)
      for (const Residue& res : chain.residues)
        for (const Atom& a : res.atoms)
          table.set(a.element.ordinal());
    return table;
  }

  /// @brief Create a shallow copy with metadata but empty chains.
  /// Used in template code for hierarchical copying.
  Model empty_copy() const { return Model(num); }

  using child_type = Chain;
  /// @brief Access mutable chains vector.
  std::vector<Chain>& children() { return chains; }
  /// @brief Access const chains vector.
  const std::vector<Chain>& children() const { return chains; }
};

/// @brief Find entity containing given subchain.
/// Searches for an entity that includes the specified subchain ID.
/// @param subchain_id Subchain identifier to search for
/// @param entities Vector of entities to search
/// @return Pointer to entity containing this subchain, or nullptr if not found
inline Entity* find_entity_of_subchain(const std::string& subchain_id,
                                       std::vector<Entity>& entities) {
  if (!subchain_id.empty())
    for (Entity& ent : entities)
      if (in_vector(subchain_id, ent.subchains))
        return &ent;
  return nullptr;
}

/// @copydoc find_entity_of_subchain(const std::string&, std::vector<Entity>&)
inline const Entity* find_entity_of_subchain(const std::string& subchain_id,
                                             const std::vector<Entity>& entities) {
  return find_entity_of_subchain(subchain_id, const_cast<std::vector<Entity>&>(entities));
}

/// @brief Represents a complete macromolecular structure with coordinates and metadata.
/// The top level of the data hierarchy containing models, chains, residues, and atoms,
/// along with crystallographic, NMR, and biological assembly information.
struct Structure {
  static const char* what() { return "Structure"; }
  std::string name;                  ///< Structure name (e.g., PDB code)
  UnitCell cell;                     ///< Unit cell parameters (a, b, c, alpha, beta, gamma)
  std::string spacegroup_hm;         ///< Space group symbol (PDB/Hermann-Mauguin notation)
  std::vector<Model> models;         ///< NMR models or ensemble structures
  std::vector<NcsOp> ncs;            ///< Non-crystallographic symmetry operators
  std::vector<Entity> entities;      ///< Polymer and ligand entity definitions
  std::vector<Connection> connections; ///< Chemical bonds and other connections
  std::vector<CisPep> cispeps;       ///< Cis-peptide bonds (non-standard geometry)
  std::vector<ModRes> mod_residues;  ///< Modified residue descriptions
  std::vector<StructSite> sites;     ///< Special sites (binding sites, etc.)
  std::vector<Helix> helices;        ///< Secondary structure: helices
  std::vector<Sheet> sheets;         ///< Secondary structure: beta sheets
  std::vector<Assembly> assemblies;  ///< Biological assemblies (quaternary structure)
  std::map<int, std::vector<int>> conect_map; ///< PDB CONECT records by atom serial
  Metadata meta;                     ///< File metadata (authors, publication, etc.)

  CoorFormat input_format = CoorFormat::Unknown; ///< Format of input file (PDB, mmCIF, etc.)
  bool has_d_fraction = false;       ///< Flag: uses Refmac's ccp4_deuterium_fraction
  int non_ascii_line = 0;            ///< First PDB line with non-ASCII bytes (0 = none)
  /// @brief Status of TER records in PDB file.
  /// '\0' = not set, 'y' = TER records were read, 'e' = errors detected
  char ter_status = '\0';

  bool has_origx = false;            ///< Flag: ORIGX transformation matrix present
  Transform origx;                   ///< ORIGX or _database_PDB_matrix transformation

  std::map<std::string, std::string> info;  ///< Minimal metadata with mmCIF tag keys
  std::map<std::string, ChemComp> chemcomps; ///< ChemComp data from mmCIF, keyed by ID
  /// @brief Mapping of long (4+ chars) CCD codes to PDB-compatible 3-letter codes
  std::vector<std::pair<std::string,std::string>> shortened_ccd_codes;
  std::vector<std::string> raw_remarks;  ///< Original REMARK records from PDB file
  double resolution = 0;             ///< Resolution from REMARK 2 (0 = not set, in Å)

  /// @brief Find space group definition based on cell parameters.
  /// @return Pointer to SpaceGroup, or nullptr if not a crystal (aperiodic) structure
  const SpaceGroup* find_spacegroup() const {
    if (!cell.is_crystal())
      return nullptr;
    return find_spacegroup_by_name(spacegroup_hm, cell.alpha, cell.gamma);
  }

  /// @brief Get metadata value by mmCIF tag key.
  /// @param tag mmCIF tag (e.g., "_entry.id", "_cell.Z_PDB")
  /// @return Value of tag, or empty string if not found
  const std::string& get_info(const std::string& tag) const {
    static const std::string empty;
    auto it = info.find(tag);
    return it != info.end() ? it->second : empty;
  }

  /// @brief Get first model in structure.
  /// @return Reference to first model
  /// @throws fail() if no models exist
  Model& first_model() {
    if (models.empty())
      fail("no structural models");
    return models[0];
  }
  /// @copydoc first_model()
  const Model& first_model() const {
    return const_cast<Structure*>(this)->first_model();
  }

  /// @brief Find model by number.
  /// @param model_num Model number to search for
  /// @return Pointer to model, or nullptr if not found
  Model* find_model(int model_num) {
    return impl::find_or_null(models, model_num);
  }
  /// @copydoc find_model()
  const Model* find_model(int model_num) const {
    return const_cast<Structure*>(this)->find_model(model_num);
  }

  /// @brief Find model by number, creating it if necessary.
  /// @param model_num Model number to find or create
  /// @return Reference to existing or newly created model
  Model& find_or_add_model(int model_num) {
    return impl::find_or_add(models, model_num);
  }

  /// @brief Renumber all models sequentially (1, 2, 3, ...).
  void renumber_models() {
    for (size_t i = 0; i != models.size(); ++i)
      models[i].num = i + 1;
  }

  /// @brief Find entity by ID.
  /// @param ent_id Entity identifier
  /// @return Pointer to entity, or nullptr if not found
  Entity* get_entity(const std::string& ent_id) {
    return impl::find_or_null(entities, ent_id);
  }
  /// @copydoc get_entity()
  const Entity* get_entity(const std::string& ent_id) const {
    return const_cast<Structure*>(this)->get_entity(ent_id);
  }

  /// @brief Find entity that contains given residue span (subchain).
  /// @param sub Residue span (subchain) to query
  /// @return Pointer to entity, or nullptr if not found or span is empty
  Entity* get_entity_of(const ConstResidueSpan& sub) {
    return sub ? find_entity_of_subchain(sub.subchain_id(), entities) : nullptr;
  }
  /// @copydoc get_entity_of()
  const Entity* get_entity_of(const ConstResidueSpan& sub) const {
    return const_cast<Structure*>(this)->get_entity_of(sub);
  }

  /// @brief Find biological assembly by ID.
  /// @param assembly_id Assembly identifier
  /// @return Pointer to assembly, or nullptr if not found
  Assembly* find_assembly(const std::string& assembly_id) {
    return impl::find_or_null(assemblies, assembly_id);
  }

  /// @brief Find connection (bond) by name identifier.
  /// @param conn_name Connection name (e.g., "BOND_1")
  /// @return Pointer to connection, or nullptr if not found
  Connection* find_connection_by_name(const std::string& conn_name) {
    return impl::find_or_null(connections, conn_name);
  }
  /// @copydoc find_connection_by_name()
  const Connection* find_connection_by_name(const std::string& conn_name) const {
    return const_cast<Structure*>(this)->find_connection_by_name(conn_name);
  }

  /// @brief Find connection between two atoms specified as Chain-Residue-Atom triples.
  /// Matches atoms in either order.
  /// @param cra1 First atom specification
  /// @param cra2 Second atom specification
  /// @param ignore_segment If true, ignore segment ID in matching
  /// @return Pointer to connection, or nullptr if not found
  Connection* find_connection_by_cra(const const_CRA& cra1,
                                     const const_CRA& cra2,
                                     bool ignore_segment=false) {
    for (Connection& c : connections)
      if ((atom_matches(cra1, c.partner1, ignore_segment) &&
           atom_matches(cra2, c.partner2, ignore_segment)) ||
          (atom_matches(cra1, c.partner2, ignore_segment) &&
           atom_matches(cra2, c.partner1, ignore_segment)))
        return &c;
    return nullptr;
  }

  /// @brief Find connection between two atoms specified as AtomAddresses.
  /// Matches atoms in either order.
  /// @param a1 First atom address
  /// @param a2 Second atom address
  /// @return Pointer to connection, or nullptr if not found
  Connection* find_connection(const AtomAddress& a1, const AtomAddress& a2) {
    for (Connection& c : connections)
      if ((a1 == c.partner1 && a2 == c.partner2) ||
          (a1 == c.partner2 && a2 == c.partner1))
        return &c;
    return nullptr;
  }

  /// @brief Count NCS operators that are explicitly given (not generated).
  /// @return Number of given NCS operations
  size_t ncs_given_count() const {
    return std::count_if(ncs.begin(), ncs.end(), [](const NcsOp& o) { return o.given; });
  }

  /// @brief Get multiplier for calculating expected multiplicity from NCS.
  /// Equals (number_of_ncs_ops + 1) / (number_of_given_ncs + 1).
  /// @return NCS multiplier factor
  double get_ncs_multiplier() const {
    return (ncs.size() + 1.0) / (ncs_given_count() + 1.0);  // +1 b/c identity not included
  }

  /// @brief Check if NCS operations are not fully expanded.
  /// @return true if any NCS operator is not marked as given
  bool ncs_not_expanded() const {
    return std::any_of(ncs.begin(), ncs.end(), [](const NcsOp& o) { return !o.given; });
  }

  /// @brief Add bond(s) from one atom to another in one direction only.
  /// Used internally by add_conect() to build the CONECT map.
  /// @param serial_a Serial number of first atom
  /// @param serial_b Serial number of second atom
  /// @param order Bond order (number of edges to add)
  void add_conect_one_way(int serial_a, int serial_b, int order) {
    auto& vec = conect_map[serial_a];
    for (int i = 0; i < order; ++i)
      vec.insert(std::upper_bound(vec.begin(), vec.end(), serial_b), serial_b);
  }
  /// @brief Add bidirectional bond(s) between two atoms.
  /// Adds edges in both directions (serial1->serial2 and serial2->serial1).
  /// @param serial1 Serial number of first atom
  /// @param serial2 Serial number of second atom
  /// @param order Bond order (number of edges to add in each direction)
  void add_conect(int serial1, int serial2, int order) {
    add_conect_one_way(serial1, serial2, order);
    add_conect_one_way(serial2, serial1, order);
  }

  /// @brief Merge consecutive chains with the same name across all models.
  /// @param min_sep Minimum sequence number separation between merged chains
  void merge_chain_parts(int min_sep=0) {
    for (Model& model : models)
      model.merge_chain_parts(min_sep);
  }

  /// @brief Remove all empty chains from all models.
  void remove_empty_chains() {
    for (Model& model : models)
      remove_empty_children(model);
  }

  /// @brief Create a shallow copy with metadata but empty models.
  /// Copies all fields except the models vector (which remains empty).
  /// Used in template code for hierarchical copying.
  /// @return New Structure with metadata but no structural data
  Structure empty_copy() const {
    Structure st;
    st.name = name;
    st.cell = cell;
    st.spacegroup_hm = spacegroup_hm;
    st.ncs = ncs;
    st.entities = entities;
    st.connections = connections;
    st.cispeps = cispeps;
    st.mod_residues = mod_residues;
    st.sites = sites;
    st.helices = helices;
    st.sheets = sheets;
    st.assemblies = assemblies;
    st.meta = meta;
    st.input_format = input_format;
    st.has_origx = has_origx;
    st.origx = origx;
    st.info = info;
    st.raw_remarks = raw_remarks;
    st.resolution = resolution;
    return st;
  }

  using child_type = Model;
  /// @brief Access mutable models vector.
  std::vector<Model>& children() { return models; }
  /// @brief Access const models vector.
  const std::vector<Model>& children() const { return models; }

  /// @brief Set up crystallographic cell image information.
  /// Populates cell image transformations based on space group symmetry and NCS.
  void setup_cell_images();
};

inline Residue* Chain::find_residue(const ResidueId& rid) {
  auto it = std::find_if(residues.begin(), residues.end(),
                         [&](const Residue& r) { return r.matches(rid); });
  return it != residues.end() ? &*it : nullptr;
}

inline Residue* Chain::find_or_add_residue(const ResidueId& rid) {
  Residue* r = find_residue(rid);
  if (r)
    return r;
  residues.emplace_back(rid);
  return &residues.back();
}

inline void Chain::append_residues(std::vector<Residue> new_resi, int min_sep) {
  if (new_resi.empty())
    return;
  if (min_sep > 0) {
    ConstResidueSpan new_span(&new_resi[0], new_resi.size());
    // adjust sequence numbers if necessary
    auto diff = new_span.extreme_num(false, -1) - whole().extreme_num(false, 1);
    if (diff && int(diff) < min_sep)
      for (Residue& res : new_resi)
        res.seqid.num += min_sep - int(diff);
    // adjust label_seq_id if necessary
    diff = new_span.extreme_num(true, -1) - whole().extreme_num(true, 1);
    if (diff && int(diff) < min_sep)
      for (Residue& res : new_resi)
        res.label_seq += min_sep - int(diff);
  }
  std::move(new_resi.begin(), new_resi.end(), std::back_inserter(residues));
}

/// @copydoc Structure::setup_cell_images()
inline void Structure::setup_cell_images() {
  const SpaceGroup* sg = find_spacegroup();
  cell.set_cell_images_from_spacegroup(sg);
  cell.add_ncs_images_to_cs_images(ncs);
}

/// @brief Assign secondary structure annotations from HELIX and SHEET records.
/// Initializes all residues to Coil/NotStrand, then marks ranges from PDB records.
/// @param st Structure to annotate
inline void assign_residue_ss_from_file(Structure& st) {
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        res.ss_from_file = ResidueSs::Coil;
  for (Model& model : st.models)
    for (Chain& chain : model.chains)
      for (Residue& res : chain.residues)
        res.strand_sense_from_file = ResidueStrandSense::NotStrand;

  auto mark_range = [&](const AtomAddress& start, const AtomAddress& end,
                        ResidueSs ss,
                        ResidueStrandSense sense) {
    if (start.chain_name != end.chain_name)
      return;
    SeqId first = start.res_id.seqid;
    SeqId last = end.res_id.seqid;
    if (last < first)
      std::swap(first, last);
    for (Model& model : st.models)
      if (Chain* chain = model.find_chain(start.chain_name))
        for (Residue& res : chain->residues)
          if (first <= res.seqid && res.seqid <= last) {
            res.ss_from_file = ss;
            res.strand_sense_from_file = sense;
          }
  };

  for (const Helix& helix : st.helices)
    mark_range(helix.start, helix.end, ResidueSs::Helix,
               ResidueStrandSense::NotStrand);
  for (const Sheet& sheet : st.sheets)
    for (const Sheet::Strand& strand : sheet.strands)
      mark_range(strand.start, strand.end, ResidueSs::Strand,
                 strand.sense == 1 ? ResidueStrandSense::Parallel :
                 strand.sense == -1 ? ResidueStrandSense::Antiparallel :
                 ResidueStrandSense::First);
}

} // namespace gemmi

#endif

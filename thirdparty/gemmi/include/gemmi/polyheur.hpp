// Copyright 2017-2018 Global Phasing Ltd.
//
// Heuristic methods for working with chains and polymers.
// Also includes a few well-defined functions, such as removal of waters.

#ifndef GEMMI_POLYHEUR_HPP_
#define GEMMI_POLYHEUR_HPP_

#include <vector>
#include "model.hpp"
#include "util.hpp"      // for vector_remove_if

namespace gemmi {

/// Classify a residue span as peptide, RNA, DNA, or other polymer type.
/// A simplistic heuristic classification based on residue names.
/// Returns PolymerType (PeptideL, PeptideD, Rna, Dna, DnaRnaHybrid, or Unknown).
/// @param span sequence of residues to classify
/// @param ignore_entity_type if false, uses Entity type if known and consistent
/// @return PolymerType classification
GEMMI_DLL PolymerType check_polymer_type(const ConstResidueSpan& span,
                                         bool ignore_entity_type=false);

/// Determine polymer type from entity or by classification.
/// Returns the entity's polymer_type if known and non-Unknown,
/// otherwise classifies the residue span.
/// @param ent entity with known polymer type (may be nullptr)
/// @param polymer residue span to classify if entity type unknown
/// @return PolymerType classification
inline PolymerType get_or_check_polymer_type(const Entity* ent,
                                             const ConstResidueSpan& polymer) {
  if (ent && ent->polymer_type != PolymerType::Unknown)
    return ent->polymer_type;
  return check_polymer_type(polymer);
}

/// Atom name and chemical element pair.
/// Used to represent backbone atom components of a polymer type.
struct AtomNameElement { std::string atom_name; El el; };

/// Get backbone atom names and elements for a polymer type.
/// For peptides: N, CA, C, O.
/// For nucleic acids: P, O5', C5', C4', O4', C3', O3', C2', O2', C1'.
/// @param ptype polymer type (peptide or nucleic acid)
/// @return vector of {atom_name, element} pairs for the backbone
inline std::vector<AtomNameElement> get_mainchain_atoms(PolymerType ptype) {
  if (is_polynucleotide(ptype))
    return {{"P", El::P}, {"O5'", El::O}, {"C5'", El::C},
            {"C4'", El::C}, {"O4'", El::O}, {"C3'", El::C}, {"O3'", El::O},
            {"C2'", El::C}, {"O2'", El::O}, {"C1'", El::C}};
  return {{"N", El::N}, {"CA", El::C}, {"C", El::C}, {"O", El::O}};
}

/// Check if two atoms are within peptide bond distance.
/// Tests C(i)–N(i+1) distance < 2.01 Ångströms.
/// @param a1 C atom (may be nullptr)
/// @param a2 N atom (may be nullptr)
/// @return true if both atoms exist and are within bond distance
inline bool in_peptide_bond_distance(const Atom* a1, const Atom* a2) {
  return a1 && a2 && a1->pos.dist_sq(a2->pos) < sq(1.341 * 1.5);
}
/// Check if two consecutive residues are bonded by a peptide bond.
/// Tests if the C atom of r1 and N atom of r2 are within peptide bond distance.
/// @param r1 first (C-terminal) residue
/// @param r2 second (N-terminal) residue
/// @return true if peptide bond exists
inline bool have_peptide_bond(const Residue& r1, const Residue& r2) {
  return in_peptide_bond_distance(r1.get_c(), r2.get_n());
}

/// Check if two atoms are within nucleotide bond distance.
/// Tests O3'(i)–P(i+1) distance < 2.4 Ångströms.
/// @param a1 O3' atom (may be nullptr)
/// @param a2 P atom (may be nullptr)
/// @return true if both atoms exist and are within bond distance
inline bool in_nucleotide_bond_distance(const Atom* a1, const Atom* a2) {
  return a1 && a2 && a1->pos.dist_sq(a2->pos) < sq(1.6 * 1.5);
}
/// Check if two consecutive residues are bonded by a phosphodiester bond.
/// Tests if the O3' atom of r1 and P atom of r2 are within nucleotide bond distance.
/// @param r1 first residue
/// @param r2 second (following) residue
/// @return true if phosphodiester bond exists
inline bool have_nucleotide_bond(const Residue& r1, const Residue& r2) {
  return in_nucleotide_bond_distance(r1.get_o3prim(), r2.get_p());
}

/// Strict connectivity check using actual bond atoms.
/// For peptides: tests C-N distance; for nucleotides: tests O3'-P distance.
/// @param r1 first residue
/// @param r2 second residue
/// @param ptype polymer type (peptide or nucleic acid)
/// @return true if residues are bonded
inline bool are_connected(const Residue& r1, const Residue& r2, PolymerType ptype) {
  if (is_polypeptide(ptype))
    return have_peptide_bond(r1, r2);
  if (is_polynucleotide(ptype))
    return have_nucleotide_bond(r1, r2);
  return false;
}

/// Loose connectivity check using only alpha-carbon or phosphorus atoms.
/// For peptides: tests Cα–Cα < 5 Å; for nucleotides: tests P–P < 7.5 Å.
/// Requires only Cα or P atoms, not full backbone atoms.
/// @param r1 first residue
/// @param r2 second residue
/// @param ptype polymer type (peptide or nucleic acid)
/// @return true if residues appear connected by distance
inline bool are_connected2(const Residue& r1, const Residue& r2, PolymerType ptype) {
  auto this_or_first = [](const Atom* a, const Residue& r, El el) -> const Atom* {
    if (a || r.atoms.empty())
      return a;
    if (const Atom* b = r.find_by_element(el))
      return b;
    return &r.atoms.front();
  };
  if (is_polypeptide(ptype)) {
    const Atom* a1 = this_or_first(r1.get_ca(), r1, El::C);
    const Atom* a2 = this_or_first(r2.get_ca(), r2, El::C);
    return a1 && a2 && a1->pos.dist_sq(a2->pos) < sq(5.0);
  }
  if (is_polynucleotide(ptype)) {
    const Atom* a1 = this_or_first(r1.get_p(), r1, El::P);
    const Atom* a2 = this_or_first(r2.get_p(), r2, El::P);
    return a1 && a2 && a1->pos.dist_sq(a2->pos) < sq(7.5);
  }
  return false;
}

/// Connectivity check with fallback from strict to loose criteria.
/// First tries are_connected() with actual bond atoms,
/// then falls back to are_connected2() using Cα or P distances.
/// @param r1 first residue
/// @param r2 second residue
/// @param ptype polymer type (peptide or nucleic acid)
/// @return true if residues are connected by either criterion
inline bool are_connected3(const Residue& r1, const Residue& r2, PolymerType ptype) {
  if (is_polypeptide(ptype)) {
    if (const Atom* a1 = r1.get_c())
      if (const Atom* a2 = r2.get_n())
        return a1->pos.dist_sq(a2->pos) < sq(1.341 * 1.5);
    if (const Atom* a1 = r1.get_ca())
      if (const Atom* a2 = r2.get_ca())
        return a1->pos.dist_sq(a2->pos) < sq(5.0);
  } else if (is_polynucleotide(ptype)) {
    if (const Atom* a1 = r1.get_o3prim())
      if (const Atom* a2 = r2.get_p())
        return a1->pos.dist_sq(a2->pos) < sq(1.6 * 1.5);
    if (const Atom* a1 = r1.get_p())
      if (const Atom* a2 = r2.get_p())
        return a1->pos.dist_sq(a2->pos) < sq(7.5);
  }
  return false;
}

/// Convert polymer residues to one-letter sequence codes.
/// Translates residue names to standard IUPAC single-letter codes.
/// Unknown residues become 'X'.
/// @param polymer sequence of residues to convert
/// @return one-letter sequence string
GEMMI_DLL std::string make_one_letter_sequence(const ConstResidueSpan& polymer);

/// Assign entity types to residues in a chain.
/// Assigns entity_type=Polymer|NonPolymer|Water to each residue.
/// Only updates residues with entity_type==Unknown unless overwrite=true.
/// Note: determining polymer/ligand boundary can be ambiguous for non-standard residues.
/// @param chain chain to annotate
/// @param overwrite if true, reassign types even for known residues
GEMMI_DLL void add_entity_types(Chain& chain, bool overwrite);

/// Assign entity types to all chains in a structure.
/// @param st structure to annotate
/// @param overwrite if true, reassign types even for known residues
GEMMI_DLL void add_entity_types(Structure& st, bool overwrite);

/// Reset all residue entity types to Unknown.
/// @param st structure to modify
GEMMI_DLL void remove_entity_types(Structure& st);

/// Assign entity IDs to residues based on subchain assignments.
/// Links Residue::entity_id to Entity records via Residue::subchain and Entity::subchains.
/// @param st structure to annotate
/// @param overwrite if true, reassign IDs even for residues that already have them
GEMMI_DLL void add_entity_ids(Structure& st, bool overwrite);

/// Assign subchain labels to residues in a chain.
/// Splits the chain into segments: linear polymers, non-polymers (each with unique ID),
/// and waters. Stores label_asym_id-like names in Residue::subchain.
/// wwPDB software splits auth_asym_id into label_asym_id units similarly.
/// This function uses compatible but distinct naming and rules.
/// @param chain chain to segment
/// @param nonpolymer_counter incremented for each non-polymer segment (input/output)
/// @note call add_entity_types() first to set entity types correctly
GEMMI_DLL void assign_subchain_names(Chain& chain, int& nonpolymer_counter);

/// Assign subchain names to all chains in a structure.
/// Calls assign_subchain_names on each chain to segment into polymer/non-polymer units.
/// @param st structure to annotate
/// @param force if true, reassign subchains even if already assigned
/// @param fail_if_unknown if true, raise error if polymer type is unknown; if false, skip
GEMMI_DLL void assign_subchains(Structure& st, bool force, bool fail_if_unknown=true);

/// Create missing Entity records for all subchains in the structure.
/// Ensures each Residue::subchain has a corresponding Entity.
/// @param st structure to update
GEMMI_DLL void ensure_entities(Structure& st);

/// Merge Entity records with identical sequences into one.
/// Consolidates duplicate sequence entries and updates residue entity_ids.
/// @param st structure to deduplicate
GEMMI_DLL void deduplicate_entities(Structure& st);

/// Set up entity metadata for a structure in a standard workflow.
/// Convenience function that calls add_entity_types + assign_subchains +
/// ensure_entities + deduplicate_entities in sequence.
/// @param st structure to set up
inline void setup_entities(Structure& st) {
  add_entity_types(st, /*overwrite=*/false);
  assign_subchains(st, /*force=*/false);
  ensure_entities(st);
  deduplicate_entities(st);
}

/// Determine ATOM/HETATM record type based on residue entity type.
/// Returns 'A' (ATOM) for polymers or 'H' (HETATM) for non-polymers and waters.
/// @param res residue to classify
/// @return 'A' or 'H'
GEMMI_DLL char recommended_het_flag(const Residue& res);

/// Assign het_flag to all residues in an object.
/// @tparam T Model, Chain, or Residue
/// @param obj object to modify
/// @param flag het_flag value: 'A' (ATOM), 'H' (HETATM), 'R' (recommended), or ' ' (none)
template<class T> void assign_het_flags(T& obj, char flag='R') {
  for (auto& child : obj.children())
    assign_het_flags(child, flag);
}
template<> inline void assign_het_flags(Residue& res, char flag) {
  flag &= ~0x20; // uppercase letters, ' ' -> \0
  if (flag != 'R' && flag != '\0' && flag != 'A' && flag != 'H')
    fail("assign_het_flags(): the only allowed values are A, H, ' ' and R");
  res.het_flag = flag == 'R' ? recommended_het_flag(res) : flag;
}

/// Remove water residues from a structure or chain.
/// May leave empty chains if all residues are waters.
/// @tparam T Model, Chain, or Residue
/// @param obj object to modify
template<class T> void remove_waters(T& obj) {
  for (auto& child : obj.children())
    remove_waters(child);
}
template<> inline void remove_waters(Chain& ch) {
  vector_remove_if(ch.residues,
                   [](const Residue& res) { return res.is_water(); });
}

/// Remove all non-polymer residues (ligands and waters).
/// Requires entity_type to be assigned first (see add_entity_types).
/// May leave empty chains if all residues are removed.
/// @tparam T Model, Chain, or Residue
/// @param obj object to modify
template<class T> void remove_ligands_and_waters(T& obj) {
  for (auto& child : obj.children())
    remove_ligands_and_waters(child);
}
template<> inline void remove_ligands_and_waters(Chain& ch) {
  vector_remove_if(ch.residues, [&](const Residue& res) {
      if (res.entity_type == EntityType::Unknown)
        fail("remove_ligands_and_waters(): missing entity_type in chain ", ch.name);
      return res.entity_type != EntityType::Polymer;
  });
}

/// Reduce an amino acid residue to an alanine backbone.
/// Removes all side-chain atoms, keeping only N, CA, C, O and CB.
/// @param res residue to trim
/// @return true if trimmed successfully, false if residue is not a standard amino acid
GEMMI_DLL bool trim_to_alanine(Residue& res);

/// Trim all amino acid residues in a chain to alanine.
/// @param chain chain to modify
inline void trim_to_alanine(Chain& chain) {
  for (Residue& res : chain.residues)
    trim_to_alanine(res);
}

/// Convert long CCD codes to 3-letter abbreviations for PDB format compatibility.
/// Refmac does similar shortening. Enables Refmac refinement with long residue names.
/// @param st structure to modify
GEMMI_DLL void shorten_ccd_codes(Structure& st);

/// Restore full CCD codes from their 3-letter abbreviations.
/// Inverse of shorten_ccd_codes(); uses stored abbreviation mappings.
/// @param st structure to modify
GEMMI_DLL void restore_full_ccd_codes(Structure& st);

/// Annotate microheterogeneity positions in entity sequences.
/// Identifies residue positions with multiple alternate conformations and
/// marks them in Entity::full_sequence. Uses only the first chain for each entity.
/// @param st structure to annotate
/// @param overwrite if true, overwrite existing microheterogeneity annotations
GEMMI_DLL void add_microhetero_to_sequences(Structure& st, bool overwrite=false);

/// Assign sequential integer IDs to all TLS groups in the structure.
/// @param st structure to annotate
GEMMI_DLL void add_tls_group_ids(Structure& st);

} // namespace gemmi
#endif

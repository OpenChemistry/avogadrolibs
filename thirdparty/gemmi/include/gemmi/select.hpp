// Copyright 2018 Global Phasing Ltd.
//
// Selections.

#ifndef GEMMI_SELECT_HPP_
#define GEMMI_SELECT_HPP_

#include <climits>   // for INT_MIN, INT_MAX
#include "model.hpp" // for Model

namespace gemmi {

// from http://www.ccp4.ac.uk/html/pdbcur.html
// Specification of the selection sets:
// either
//     /mdl/chn/s1.i1-s2.i2/at[el]:aloc
// or
//     /mdl/chn/*(res).ic/at[el]:aloc
//

/// Parsed CCP4-style atom/residue/chain selection expression.
///
/// Represents a selection filter such as "//A/10-20/CA[C].B" for filtering
/// atoms, residues, chains, and models from a structure. Provides both
/// individual match predicates and FilterProxy views for convenient iteration
/// over matching elements.
struct GEMMI_DLL Selection {
  /// Set of allowed names with optional inversion.
  ///
  /// Represents comma-separated lists like "ALA,GLY" with optional
  /// inversion to mean "everything except".
  struct List {
    /// If true, matches everything (corresponding to "*")
    bool all = true;
    /// If true, the match logic is inverted (names NOT in list)
    bool inverted = false;
    /// Comma-separated list of names
    std::string list;

    /// Get the canonical string representation.
    ///
    /// @return "*" if all=true, else the list optionally prefixed with "!"
    std::string str() const {
      if (all)
        return "*";
      return inverted ? "!" + list : list;
    }

    /// Check if a name matches this list.
    ///
    /// Accounts for the all and inverted flags.
    ///
    /// @param name The name to check
    /// @return true if the name matches according to all and inverted settings
    bool has(const std::string& name) const {
      if (all)
        return true;
      bool found = is_in_list(name, list);
      return inverted ? !found : found;
    }
  };

  /// Matches a single character flag against a pattern string.
  ///
  /// Supports optional inversion with a leading '!' character.
  struct FlagList {
    /// Flag characters; may be prefixed with '!' to invert the match
    std::string pattern;

    /// Check if a flag appears in the pattern.
    ///
    /// If pattern begins with '!', returns true if the flag does NOT appear
    /// in the rest of the pattern.
    ///
    /// @param flag The flag character to check
    /// @return true if the flag matches the pattern (or does not match if inverted)
    bool has(char flag) const {
      if (pattern.empty())
        return true;
      bool invert = (pattern[0] == '!');
      bool found = (pattern.find(flag, invert ? 1 : 0) != std::string::npos);
      return invert ? !found : found;
    }
  };

  /// A residue sequence position for range matching.
  ///
  /// Represents a single point in the residue sequence, with an optional
  /// insertion code. Special values INT_MIN and INT_MAX represent unset bounds.
  struct SequenceId {
    /// Integer sequence number (INT_MIN = unset lower bound, INT_MAX = unset upper bound)
    int seqnum;
    /// Insertion code character ('*' = wildcard)
    char icode;

    /// Check if this sequence ID is unset.
    ///
    /// @return true if seqnum is INT_MIN or INT_MAX
    bool empty() const {
      return seqnum == INT_MIN || seqnum == INT_MAX;
    }

    /// Get the string representation of this sequence ID.
    ///
    /// @return String like "10" or "10A" depending on icode
    std::string str() const;

    /// Compare this sequence ID to another SeqId.
    ///
    /// Compares first by sequence number, then by insertion code if needed.
    /// The wildcard '*' for icode matches any insertion code.
    ///
    /// @param seqid The SeqId to compare to
    /// @return negative if less than, 0 if equal, positive if greater than seqid
    int compare(const SeqId& seqid) const {
      if (seqnum != *seqid.num)
        return seqnum < *seqid.num ? -1 : 1;
      if (icode != '*' && icode != seqid.icode)
        return icode < seqid.icode ? -1 : 1;
      return 0;
    }
  };

  /// A numeric filter on atom properties (occupancy or B-factor).
  ///
  /// Represents a constraint like "q>0.5" (occupancy greater than 0.5)
  /// or "b<30" (B-factor less than 30).
  struct AtomInequality {
    /// Property character: 'q' for occupancy, 'b' for B-factor
    char property;
    /// Relation: -1 for less than, 0 for equals, +1 for greater than
    int relation;
    /// The threshold value to compare against
    double value;

    /// Check if an atom satisfies this inequality.
    ///
    /// Extracts the specified property from the atom and compares it
    /// to the threshold using the specified relation.
    ///
    /// @param a The atom to check
    /// @return true if the atom's property satisfies the inequality
    bool matches(const Atom& a) const {
      double atom_value = 0.;
      if (property == 'q')
        atom_value = a.occ;
      else if (property == 'b')
        atom_value = a.b_iso;
      if (relation < 0)
        return atom_value < value;
      if (relation > 0)
        return atom_value > value;
      return atom_value == value;
    }

    /// Get the string representation of this inequality.
    ///
    /// @return String like "q>0.5" or "b<30"
    std::string str() const;
  };

  /// Model number to select (0 = all models)
  int mdl = 0;
  /// List of allowed chain IDs
  List chain_ids;
  /// Start of sequence ID range (inclusive)
  SequenceId from_seqid = {INT_MIN, '*'};
  /// End of sequence ID range (inclusive)
  SequenceId to_seqid = {INT_MAX, '*'};
  /// List of allowed residue names (3-letter codes)
  List residue_names;
  /// List of allowed entity type strings
  List entity_types;
  /// Flags array for entity type matching (corresponds to enum EntityType)
  std::array<char, 6> et_flags;
  /// List of allowed atom names
  List atom_names;
  /// Vector of allowed element numbers
  std::vector<char> elements;
  /// List of allowed alternate conformer IDs
  List altlocs;
  /// Flag-based filter for residues
  FlagList residue_flags;
  /// Flag-based filter for atoms
  FlagList atom_flags;
  /// Vector of numeric property filters
  std::vector<AtomInequality> atom_inequalities;

  /// Default constructor.
  Selection() = default;

  /// Parse a CCP4 selection string.
  ///
  /// Parses a selection string like "//A/10-20/CA[C].B" into the
  /// selection criteria.
  ///
  /// @param cid The CCP4-style selection string
  Selection(const std::string& cid);

  /// Get the canonical string representation of this selection.
  ///
  /// @return String representation of the parsed selection
  std::string str() const;

  /// Check if a structure matches this selection.
  ///
  /// Structures always match (they are never filtered).
  ///
  /// @param s The structure to check
  /// @return Always true
  bool matches(const Structure&) const { return true; }

  /// Check if a model matches this selection.
  ///
  /// Matches if the model number is 0 (select all) or matches mdl.
  ///
  /// @param model The model to check
  /// @return true if the model is included in this selection
  bool matches(const Model& model) const {
    return mdl == 0 || mdl == model.num;
  }

  /// Check if a chain matches this selection.
  ///
  /// Matches if the chain ID is in the allowed list.
  ///
  /// @param chain The chain to check
  /// @return true if the chain is included in this selection
  bool matches(const Chain& chain) const {
    return chain_ids.has(chain.name);
  }

  /// Check if a residue matches this selection.
  ///
  /// Matches residue name, sequence ID range, entity type, and flags.
  ///
  /// @param res The residue to check
  /// @return true if the residue is included in this selection
  bool matches(const Residue& res) const {
    return (entity_types.all || et_flags[(int)res.entity_type]) &&
           residue_names.has(res.name) &&
           from_seqid.compare(res.seqid) <= 0 &&
           to_seqid.compare(res.seqid) >= 0 &&
           residue_flags.has(res.flag);
  }

  /// Check if an atom matches this selection.
  ///
  /// Matches atom name, element, altloc, flags, and numeric inequalities.
  ///
  /// @param a The atom to check
  /// @return true if the atom is included in this selection
  bool matches(const Atom& a) const {
    return atom_names.has(a.name) &&
           (elements.empty() || elements[a.element.ordinal()]) &&
           (altlocs.all || altlocs.has(std::string(a.altloc ? 1 : 0, a.altloc))) &&
           atom_flags.has(a.flag) &&
           std::all_of(atom_inequalities.begin(), atom_inequalities.end(),
                       [&](const AtomInequality& i) { return i.matches(a); });
  }

  /// Check if a chain-residue-atom triplet matches this selection.
  ///
  /// Matches if all non-null components pass their respective match tests.
  ///
  /// @param cra The CRA structure to check
  /// @return true if the CRA is included in this selection
  bool matches(const CRA& cra) const {
    return (cra.chain == nullptr || matches(*cra.chain)) &&
           (cra.residue == nullptr || matches(*cra.residue)) &&
           (cra.atom == nullptr || matches(*cra.atom));
  }

  /// Get a filtered view over models in a structure.
  ///
  /// @param st The structure to filter
  /// @return A FilterProxy that iterates over matching models
  FilterProxy<Selection, Model> models(Structure& st) const {
    return {*this, st.models};
  }

  /// Get a filtered view over chains in a model.
  ///
  /// @param model The model to filter
  /// @return A FilterProxy that iterates over matching chains
  FilterProxy<Selection, Chain> chains(Model& model) const {
    return {*this, model.chains};
  }

  /// Get a filtered view over residues in a chain.
  ///
  /// @param chain The chain to filter
  /// @return A FilterProxy that iterates over matching residues
  FilterProxy<Selection, Residue> residues(Chain& chain) const {
    return {*this, chain.residues};
  }

  /// Get a filtered view over atoms in a residue.
  ///
  /// @param residue The residue to filter
  /// @return A FilterProxy that iterates over matching atoms
  FilterProxy<Selection, Atom> atoms(Residue& residue) const {
    return {*this, residue.atoms};
  }

  /// Find the first matching atom in a model.
  ///
  /// Searches through the model's chains and residues to find the first
  /// atom that matches this selection.
  ///
  /// @param model The model to search
  /// @return A CRA with the first match, or {nullptr, nullptr, nullptr} if not found
  CRA first_in_model(Model& model) const {
    if (matches(model))
      for (Chain& chain : model.chains) {
        if (matches(chain))
          for (Residue& res : chain.residues) {
            if (matches(res))
              for (Atom& atom : res.atoms) {
                if (matches(atom))
                  return {&chain, &res, &atom};
              }
          }
      }
    return {nullptr, nullptr, nullptr};
  }

  /// Find the first matching atom in a structure.
  ///
  /// Searches through all models to find the first matching atom.
  ///
  /// @param st The structure to search
  /// @return A pair of {Model*, CRA} with the first match, or {nullptr, empty_CRA} if not found
  std::pair<Model*, CRA> first(Structure& st) const {
    for (Model& model : st.models) {
      CRA cra = first_in_model(model);
      if (cra.chain)
        return {&model, cra};
    }
    return {nullptr, {nullptr, nullptr, nullptr}};
  }

  /// Recursively copy matching children from orig into target.
  ///
  /// Used internally by copy_selection() to recursively populate a target
  /// structure with only the matching elements.
  ///
  /// @tparam T The type of element (Model, Chain, Residue, or Atom)
  /// @param orig The original element to copy from
  /// @param target The target element to copy into
  template<typename T>
  void add_matching_children(const T& orig, T& target) const {
    for (const auto& orig_child : orig.children())
      if (matches(orig_child)) {
        target.children().push_back(orig_child.empty_copy());
        add_matching_children(orig_child, target.children().back());
      }
  }

  /// Specialization for Atom (leaf node).
  void add_matching_children(const Atom&, Atom&) const {}

  /// Set the residue flag filter pattern.
  ///
  /// @param pattern Flag pattern string (may be prefixed with '!' to invert)
  /// @return *this for method chaining
  Selection& set_residue_flags(const std::string& pattern) {
    residue_flags.pattern = pattern;
    return *this;
  }

  /// Set the atom flag filter pattern.
  ///
  /// @param pattern Flag pattern string (may be prefixed with '!' to invert)
  /// @return *this for method chaining
  Selection& set_atom_flags(const std::string& pattern) {
    atom_flags.pattern = pattern;
    return *this;
  }

  /// Create a copy of an element containing only matching children.
  ///
  /// Returns a copy of orig with all non-matching children filtered out.
  /// Recursively applies the filter to nested children.
  ///
  /// @tparam T The type of element (Structure, Model, Chain, or Residue)
  /// @param orig The original element to copy
  /// @return A new element containing only matching children
  template<typename T>
  T copy_selection(const T& orig) const {
    T copied = orig.empty_copy();
    add_matching_children(orig, copied);
    return copied;
  }

  /// Remove all matching atoms or residues in-place.
  ///
  /// Recursively removes all matching children from the element.
  /// After removing all matching children from a child, also removes
  /// any empty children.
  ///
  /// @tparam T The type of element (Model, Chain, or Residue)
  /// @param t The element to modify in-place
  template<typename T>
  void remove_selected(T& t) const {
    for (auto& child : t.children())
      if (matches(child))
        remove_selected(child);
    vector_remove_if(t.children(),
                     [&](typename T::child_type& c) { return c.children().empty(); });
  }

  /// Specialization for Residue: remove matching atoms.
  ///
  /// Optimized version that clears all atoms if the selection matches
  /// all atoms, otherwise removes atoms one by one.
  void remove_selected(Residue& res) const {
    if (atom_names.all && elements.empty() && altlocs.all &&
        atom_flags.pattern.empty() && atom_inequalities.empty())
      res.atoms.clear();
    else
      vector_remove_if(res.atoms, [&](Atom& c) { return matches(c); });
  }

  /// Remove all non-matching atoms or residues in-place.
  ///
  /// Recursively removes all non-matching children from the element,
  /// then recurses into the remaining children.
  ///
  /// @tparam T The type of element (Model, Chain, or Residue)
  /// @param t The element to modify in-place
  template<typename T>
  void remove_not_selected(T& t) const {
    vector_remove_if(t.children(), [&](typename T::child_type& c) { return !matches(c); });
    for (auto& child : t.children())
      remove_not_selected(child);
  }

  /// Specialization for Atom (leaf node, no-op).
  void remove_not_selected(Atom&) const {}
};

} // namespace gemmi
#endif

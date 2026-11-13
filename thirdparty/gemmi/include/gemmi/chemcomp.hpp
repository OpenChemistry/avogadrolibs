// Copyright 2018 Global Phasing Ltd.
//
// ChemComp - chemical component that represents a monomer from Refmac
// monomer library, or from PDB CCD.

#ifndef GEMMI_CHEMCOMP_HPP_
#define GEMMI_CHEMCOMP_HPP_

#include <string>
#include <map>
#include <vector>
#include <cmath>
#include "cifdoc.hpp"
#include "elem.hpp"  // for Element
#include "fail.hpp"  // for fail, unreachable
#include "numb.hpp"  // for as_number
#include "unitcell.hpp" // for Position
#include "util.hpp"  // for istarts_with, join_str

namespace gemmi {

struct Atom;
struct Residue;

/// Bond type enum for restraints.
enum class BondType {
  Unspec,   ///< Unspecified bond type
  Single,   ///< Single bond
  Double,   ///< Double bond
  Triple,   ///< Triple bond
  Aromatic, ///< Aromatic bond
  Deloc,    ///< Delocalized bond
  Metal     ///< Metal coordination bond
};
/// @brief Check if bond type is aromatic or delocalized.
/// @param type Bond type to check.
/// @return True if type is Aromatic or Deloc.
inline bool is_aromatic_or_deloc(BondType type) {
  return type == BondType::Aromatic || type == BondType::Deloc;
}
/// Chirality type enum for stereocenters.
enum class ChiralityType {
  Positive, ///< Positive (S/R) chirality
  Negative, ///< Negative chirality
  Both      ///< Either chirality accepted
};

/// Geometric restraints for a chemical component.
/// Stores bond, angle, torsion, chirality, and planarity restraints.
struct GEMMI_DLL Restraints {
  /// Atom identifier used in restraints.
  struct AtomId {
    int comp;           ///< Component index (1 or 2 for link restraints)
    std::string atom;   ///< Atom name

    /// @brief Equality comparison.
    bool operator==(const AtomId& o) const {
      return comp == o.comp && atom == o.atom;
    }
    /// @brief Inequality comparison.
    bool operator!=(const AtomId& o) const { return !operator==(o); }

    /// @brief Equality comparison with atom name string.
    bool operator==(const std::string& name) const { return atom == name; }
    /// @brief Inequality comparison with atom name string.
    bool operator!=(const std::string& name) const { return atom != name; }

    /// @brief Lexicographic comparison.
    bool operator<(const AtomId& o) const {
      return comp == o.comp ? atom < o.atom : comp < o.comp;
    }

    /// @brief Get the Atom from residues.
    /// @param res1 First residue to search.
    /// @param res2 Optional second residue for link restraints.
    /// @param alt Alternate location character.
    /// @param altloc2 Alternate location for second residue (rare case for links with different altloc).
    /// @return Pointer to the Atom, or nullptr if not found.
    Atom* get_from(Residue& res1, Residue* res2, char alt, char altloc2) const;
    /// @brief Const version of get_from().
    const Atom* get_from(const Residue& res1, const Residue* res2,
                         char alt, char altloc2) const;
  };

  /// @brief Get canonical lexicographic string representation of two atom names.
  /// @param name1 First atom name.
  /// @param name2 Second atom name.
  /// @return Hyphen-separated pair in lexicographic order.
  static std::string lexicographic_str(const std::string& name1,
                                       const std::string& name2) {
    return name1 < name2 ? cat(name1, '-', name2) : cat(name2, '-', name1);
  }

  /// Reference frame for bond distance measurement.
  enum class DistanceOf {
    ElectronCloud, ///< Distance to electron cloud centre
    Nucleus        ///< Distance to nucleus
  };

  /// Bond restraint between two atoms.
  struct Bond {
    /// @brief Get restraint type name.
    static const char* what() { return "bond"; }
    AtomId id1;              ///< First atom
    AtomId id2;              ///< Second atom
    BondType type;           ///< Bond type
    bool aromatic;           ///< True if part of aromatic system
    double value;            ///< Ideal bond length (Å, electron cloud)
    double esd;              ///< Estimated standard deviation of value
    double value_nucleus;    ///< Ideal length to nucleus
    double esd_nucleus;      ///< ESD of nucleus length
    std::string stereo_config = "";  ///< Stereo configuration character
    int ordinal = 0;         ///< Ordering index
    /// @brief Get string representation (non-canonical).
    std::string str() const { return cat(id1.atom, '-', id2.atom); }
    /// @brief Get canonical (lexicographic) string representation.
    std::string lexicographic_str() const {
      return Restraints::lexicographic_str(id1.atom, id2.atom);
    }
    /// @brief Get ideal bond distance.
    /// @param of Reference frame (electron cloud or nucleus).
    /// @return Ideal distance in Å.
    double distance(DistanceOf of) const {
      return of == DistanceOf::ElectronCloud ? value : value_nucleus;
    }
    /// @brief Find the other atom in the bond.
    /// @tparam T Atom identifier type (AtomId or string).
    /// @param a First atom identifier.
    /// @return Pointer to the other AtomId, or nullptr if a is not in this bond.
    template<typename T> const AtomId* other(const T& a) const {
      if (id1 == a) return &id2;
      if (id2 == a) return &id1;
      return nullptr;
    }
  };

  /// Angle restraint between three atoms.
  struct Angle {
    /// @brief Get restraint type name.
    static const char* what() { return "angle"; }
    AtomId id1;     ///< First atom
    AtomId id2;     ///< Central atom
    AtomId id3;     ///< Third atom
    double value;   ///< Ideal angle in degrees
    double esd;     ///< Estimated standard deviation in degrees
    /// @brief Convert ideal angle to radians.
    /// @return Ideal angle in radians.
    double radians() const { return rad(value); }
    /// @brief Get string representation.
    std::string str() const {
      return cat(id1.atom, '-', id2.atom, '-', id3.atom);
    }
  };

  /// Torsion (dihedral) restraint between four atoms.
  struct Torsion {
    /// @brief Get restraint type name.
    static const char* what() { return "torsion"; }
    std::string label; ///< Torsion identifier string
    AtomId id1;        ///< First atom
    AtomId id2;        ///< Second atom (first bond partner)
    AtomId id3;        ///< Third atom (second bond partner)
    AtomId id4;        ///< Fourth atom
    double value = NAN;  ///< Ideal torsion angle in degrees
    double esd = 0.0;    ///< Estimated standard deviation in degrees
    int period = 0;      ///< Periodicity of the torsion
    /// @brief Get string representation.
    std::string str() const {
      return cat(id1.atom, '-', id2.atom, '-', id3.atom, '-', id4.atom);
    }
  };

  /// Chirality (stereochemistry) restraint for a stereocenter.
  struct Chirality {
    /// @brief Get restraint type name.
    static const char* what() { return "chirality"; }
    AtomId id_ctr;  ///< Chiral centre atom
    AtomId id1;     ///< First substituent
    AtomId id2;     ///< Second substituent
    AtomId id3;     ///< Third substituent
    ChiralityType sign;  ///< Expected chirality type

    /// @brief Check if observed chiral volume contradicts expected chirality.
    /// @param volume Computed chiral volume.
    /// @return True if the sign of volume disagrees with expected chirality.
    bool is_wrong(double volume) const {
      return (sign == ChiralityType::Positive && volume < 0) ||
             (sign == ChiralityType::Negative && volume > 0);
    }
    /// @brief Get string representation.
    std::string str() const {
      return cat(id_ctr.atom, ',', id1.atom, ',', id2.atom, ',', id3.atom);
    }
  };

  /// Planarity restraint for a group of atoms.
  struct Plane {
    /// @brief Get restraint type name.
    static const char* what() { return "plane"; }
    std::string label;        ///< Plane identifier string
    std::vector<AtomId> ids;  ///< Atoms defining the plane
    double esd;               ///< Estimated standard deviation of planarity restraint
    /// @brief Get string representation.
    std::string str() const {
      return join_str(ids, ',', [](const AtomId& a) { return a.atom; });
    }
  };

  std::vector<Bond> bonds;         ///< Bond restraints
  std::vector<Angle> angles;       ///< Angle restraints
  std::vector<Torsion> torsions;   ///< Torsion restraints
  std::vector<Chirality> chirs;    ///< Chirality restraints
  std::vector<Plane> planes;       ///< Planarity restraints

  /// @brief Check if all restraint lists are empty.
  /// @return True if there are no restraints of any type.
  bool empty() const {
    return bonds.empty() && angles.empty() && torsions.empty() &&
           chirs.empty() && planes.empty();
  }

  /// @brief Find a Bond between two atoms.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param a1 First atom.
  /// @param a2 Second atom.
  /// @return Iterator to the Bond, or bonds.end() if not found.
  /// @note Bond order (a1, a2 vs a2, a1) is not significant.
  template<typename T>
  std::vector<Bond>::iterator find_bond(const T& a1, const T& a2) {
    return std::find_if(bonds.begin(), bonds.end(), [&](const Bond& b) {
        return (b.id1 == a1 && b.id2 == a2) || (b.id1 == a2 && b.id2 == a1);
    });
  }
  /// @brief Const version of find_bond().
  template<typename T>
  std::vector<Bond>::const_iterator find_bond(const T& a1, const T& a2) const {
    return const_cast<Restraints*>(this)->find_bond(a1, a2);
  }
  /// @brief Get a Bond between two atoms (throw if not found).
  /// @param a1 First atom.
  /// @param a2 Second atom.
  /// @return Reference to the Bond.
  /// @throws Calls fail() if bond is not found.
  const Bond& get_bond(const AtomId& a1, const AtomId& a2) const {
    auto it = find_bond(a1, a2);
    if (it == bonds.end())
      fail("Bond restraint not found: ", a1.atom, '-', a2.atom);
    return *it;
  }

  /// @brief Check if two atoms are directly bonded.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param a1 First atom.
  /// @param a2 Second atom.
  /// @return True if a bond exists between a1 and a2.
  template<typename T>
  bool are_bonded(const T& a1, const T& a2) const {
    return find_bond(a1, a2) != bonds.end();
  }

  /// @brief Find the first atom bonded to the given atom.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param a Atom to search for bonds from.
  /// @return Pointer to the first bonded AtomId, or nullptr if none found.
  template<typename T>
  const AtomId* first_bonded_atom(const T& a) const {
    for (const Bond& bond : bonds)
      if (const AtomId* other = bond.other(a))
        return other;
    return nullptr;
  }

  /// @brief Find shortest bond path between two atoms (BFS algorithm).
  /// @param a Start atom.
  /// @param b End atom.
  /// @param visited List of initially visited atoms (to exclude from search).
  /// @param min_length Minimum path length required (default 1).
  /// @return Vector of AtomIds forming the shortest path from a to b, or empty if not found.
  std::vector<AtomId> find_shortest_path(const AtomId& a, const AtomId& b,
                                         std::vector<AtomId> visited,
                                         int min_length=1) const {
    int start = (int) visited.size();
    int end = -1;
    visited.push_back(b);
    std::vector<int> parent(visited.size(), -1);
    std::vector<int> depth(visited.size(), -1);
    depth[start] = 0;
    for (int n = start; end == -1 && n != (int) visited.size(); ++n) {
      for (const Bond& bond : bonds)
        if (const AtomId* id = bond.other(visited[n])) {
          if (*id == a) {
            int cand_len = depth[n] + 1;
            if (cand_len >= min_length) {
              end = (int) visited.size();
              if (!in_vector(*id, visited)) {
                visited.push_back(*id);
                parent.push_back(n);
                depth.push_back(cand_len);
              }
            }
          } else if (!in_vector(*id, visited)) {
            visited.push_back(*id);
            parent.push_back(n);
            depth.push_back(depth[n] + 1);
          }
        }
    }
    std::vector<AtomId> path;
    for (int n = end; n != -1; n = parent[n])
      path.push_back(visited[n]);
    return path;
  }

  /// @brief Find an Angle restraint with given atoms.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param a First atom (peripheral).
  /// @param b Central atom.
  /// @param c Third atom (peripheral).
  /// @return Iterator to the Angle, or angles.end() if not found.
  /// @note The order of peripheral atoms (a, c) is not significant.
  template<typename T>
  std::vector<Angle>::iterator find_angle(const T& a, const T& b, const T& c) {
    return std::find_if(angles.begin(), angles.end(), [&](const Angle& ang) {
        return ang.id2 == b && ((ang.id1 == a && ang.id3 == c) ||
                                (ang.id1 == c && ang.id3 == a));
    });
  }
  /// @brief Const version of find_angle().
  template<typename T> std::vector<Angle>::const_iterator
  find_angle(const T& a, const T& b, const T& c) const {
    return const_cast<Restraints*>(this)->find_angle(a, b, c);
  }
  /// @brief Get an Angle restraint with given atoms (throw if not found).
  /// @param a First atom (peripheral).
  /// @param b Central atom.
  /// @param c Third atom (peripheral).
  /// @return Reference to the Angle.
  /// @throws Calls fail() if angle restraint is not found.
  const Angle& get_angle(const AtomId& a, const AtomId& b, const AtomId& c) const {
    auto it = const_cast<Restraints*>(this)->find_angle(a, b, c);
    if (it == angles.end())
      fail("Angle restraint not found: ", a.atom, '-', b.atom, '-', c.atom);
    return *it;
  }

  /// @brief Find a Torsion restraint with given atoms.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param a First atom.
  /// @param b Second atom (first bond partner).
  /// @param c Third atom (second bond partner).
  /// @param d Fourth atom.
  /// @return Iterator to the Torsion, or torsions.end() if not found.
  /// @note Forward and reverse orderings (a-b-c-d vs d-c-b-a) are considered equivalent.
  template<typename T>
  std::vector<Torsion>::iterator find_torsion(const T& a, const T& b,
                                              const T& c, const T& d) {
    return std::find_if(torsions.begin(), torsions.end(),
                        [&](const Torsion& t) {
        return (t.id1 == a && t.id2 == b && t.id3 == c && t.id4 == d) ||
               (t.id1 == d && t.id2 == c && t.id3 == b && t.id4 == a);
    });
  }
  /// @brief Const version of find_torsion().
  template<typename T> std::vector<Torsion>::const_iterator
  find_torsion(const T& a, const T& b, const T& c, const T& d) const {
    return const_cast<Restraints*>(this)->find_torsion(a, b, c, d);
  }

  /// @brief Find a Chirality restraint for a given stereocenter.
  /// @tparam T Atom identifier type (AtomId or string).
  /// @param ctr Chiral centre atom.
  /// @param a First substituent.
  /// @param b Second substituent.
  /// @param c Third substituent.
  /// @return Iterator to the Chirality, or chirs.end() if not found.
  /// @note The order of substituents (a, b, c) is not significant.
  template<typename T>
  std::vector<Chirality>::iterator find_chir(const T& ctr, const T& a,
                                             const T& b, const T& c) {
    return std::find_if(chirs.begin(), chirs.end(), [&](const Chirality& t) {
        return t.id_ctr == ctr && ((t.id1 == a && t.id2 == b && t.id3 == c) ||
                                   (t.id1 == b && t.id2 == c && t.id3 == a) ||
                                   (t.id1 == c && t.id2 == a && t.id3 == b));
    });
  }
  /// @brief Const version of find_chir().
  template<typename T> std::vector<Chirality>::const_iterator
  find_chir(const T& ctr, const T& a, const T& b, const T& c) const {
    return const_cast<Restraints*>(this)->find_chir(ctr, a, b, c);
  }

  /// @brief Compute chiral volume from restraints.
  /// @param ch Chirality restraint.
  /// @return Absolute chiral volume computed from bond and angle restraints.
  /// @throws May call fail() if required bond or angle restraints are missing.
  double chiral_abs_volume(const Restraints::Chirality& ch) const;

  /// @brief Find a Plane by label.
  /// @param label Plane identifier string.
  /// @return Iterator to the Plane, or planes.end() if not found.
  std::vector<Plane>::iterator get_plane(const std::string& label) {
    return std::find_if(planes.begin(), planes.end(),
                        [&label](const Plane& p) { return p.label == label; });
  }

  /// @brief Get a Plane by label, creating it if absent.
  /// @param label Plane identifier string.
  /// @return Reference to the Plane (newly created with esd=0.0 if it didn't exist).
  Plane& get_or_add_plane(const std::string& label) {
    std::vector<Plane>::iterator it = get_plane(label);
    if (it != planes.end())
      return *it;
    planes.push_back(Plane{label, {}, 0.0});
    return planes.back();
  }

  /// @brief Rename an atom throughout all restraints.
  /// @param atom_id The atom to rename (identified by comp and atom name).
  /// @param new_name New atom name.
  /// @note Updates all occurrences in bonds, angles, torsions, chiralities, and planes.
  void rename_atom(const AtomId& atom_id, const std::string& new_name) {
    auto rename_atom = [&](AtomId& id) {
      if (id == atom_id)
        id.atom = new_name;
    };
    for (Bond& bond : bonds) {
      rename_atom(bond.id1);
      rename_atom(bond.id2);
    }
    for (Angle& angle : angles) {
      rename_atom(angle.id1);
      rename_atom(angle.id2);
      rename_atom(angle.id3);
    }
    for (Torsion& tor : torsions) {
      rename_atom(tor.id1);
      rename_atom(tor.id2);
      rename_atom(tor.id3);
      rename_atom(tor.id4);
    }
    for (Chirality& chir : chirs) {
      rename_atom(chir.id_ctr);
      rename_atom(chir.id1);
      rename_atom(chir.id2);
      rename_atom(chir.id3);
    }
    for (Plane& plane : planes)
      for (AtomId& id : plane.ids)
        rename_atom(id);
  }
};

/// @brief Compute z-score (deviation in standard deviations) for angle restraints.
/// @tparam Restr Restraint type with value (degrees) and esd (degrees) members.
/// @param value_rad Observed angle in radians.
/// @param restr Restraint with ideal value and standard deviation.
/// @param full Full circle in degrees (default 360, use 180 for some torsions).
/// @return Z-score = |observed - ideal| / esd.
template<typename Restr>
double angle_z(double value_rad, const Restr& restr, double full=360.) {
  return angle_abs_diff(deg(value_rad), restr.value, full) / restr.esd;
}

/// @brief Compute absolute chiral volume from bond lengths and angles.
/// @param bond1 First bond length (Å).
/// @param bond2 Second bond length (Å).
/// @param bond3 Third bond length (Å).
/// @param angle1 First angle (degrees).
/// @param angle2 Second angle (degrees).
/// @param angle3 Third angle (degrees).
/// @return Absolute chiral volume.
/// @note Uses the formula: mult * sqrt(max(0, x + y)) where mult = bond1*bond2*bond3.
inline double chiral_abs_volume(double bond1, double bond2, double bond3,
                                double angle1, double angle2, double angle3) {
  double mult = bond1 * bond2 * bond3;
  double x = 1;
  double y = 2;
  for (double a : {angle1, angle2, angle3}) {
    double cosine = a == 90. ? 0. : std::cos(rad(a));
    x -= cosine * cosine;
    y *= cosine;
  }
  return mult * std::sqrt(std::max(0., x + y));
}

inline double Restraints::chiral_abs_volume(const Restraints::Chirality& ch) const {
  return gemmi::chiral_abs_volume(get_bond(ch.id_ctr, ch.id1).value,
                                  get_bond(ch.id_ctr, ch.id2).value,
                                  get_bond(ch.id_ctr, ch.id3).value,
                                  get_angle(ch.id1, ch.id_ctr, ch.id2).value,
                                  get_angle(ch.id2, ch.id_ctr, ch.id3).value,
                                  get_angle(ch.id3, ch.id_ctr, ch.id1).value);
}

/// Chemical component (monomer) from a restraint library.
/// Represents a residue type from the Refmac monomer library or PDB CCD.
struct ChemComp {
  /// Chemical component group classification (used in _chem_comp.group and _chem_link.group_comp_N).
  enum class Group {
    Peptide,      ///< Peptide (L-amino acid)
    PPeptide,     ///< P-peptide (peptide with P configuration)
    MPeptide,     ///< M-peptide (cyclic peptide)
    Dna,          ///< DNA nucleotide
    Rna,          ///< RNA nucleotide
    DnaRna,       ///< DNA/RNA mixed nucleotide
    Pyranose,     ///< Pyranose sugar ring
    Ketopyranose, ///< Ketopyranose sugar ring
    Furanose,     ///< Furanose sugar ring
    NonPolymer,   ///< Non-polymer ligand
    Null          ///< Unset or unknown group
  };

  /// Atom in a chemical component.
  struct Atom {
    std::string id;           ///< Atom name
    std::string old_id;       ///< Legacy atom name (read from _chem_comp_atom.alt_atom_id)
    Element el = El::X;       ///< Chemical element
    float charge = 0;         ///< Formal charge (can be non-integer for partial_charge)
    std::string chem_type;    ///< CCP4 chemical type string
    std::string acedrg_type;  ///< ACEdrg atom type (read from _chem_comp_atom.atom_type)
    Position xyz{NAN, NAN, NAN};  ///< Idealized Cartesian coordinates (Å)

    /// @brief Check if this is a hydrogen atom.
    /// @return True if element is hydrogen.
    bool is_hydrogen() const { return gemmi::is_hydrogen(el); }
  };

  /// Atom naming aliasing for a specific polymer group.
  struct Aliasing {
    Group group;  ///< Polymer group this aliasing applies to
    /// Pairs of (chem_comp name, standard name in this group)
    std::vector<std::pair<std::string, std::string>> related;

    /// @brief Find chem_comp name from standard atom name.
    /// @param atom_id Standard atom name (e.g., "CA" for peptide).
    /// @return Pointer to the chem_comp atom name, or nullptr if not in aliasing.
    const std::string* name_from_alias(const std::string& atom_id) const {
      for (const auto& item : related)
        if (item.second == atom_id)
          return &item.first;
      return nullptr;
    }
  };

  std::string name;               ///< Three-letter component code
  std::string type_or_group;      ///< Raw type/group string from CIF (_chem_comp.type or _chem_comp.group)
  Group group = Group::Null;      ///< Parsed Group enum
  bool has_coordinates = false;   ///< True if xyz coordinates are available
  std::vector<Atom> atoms;        ///< Atoms in this component
  std::vector<Aliasing> aliases;  ///< Atom name aliases for different polymer groups
  Restraints rt;                  ///< Geometric restraints

  /// @brief Get atom name aliasing for a specific polymer group.
  /// @param g Group to find aliasing for.
  /// @return Reference to the Aliasing.
  /// @throws Calls fail() if aliasing is not found for this group.
  const Aliasing& get_aliasing(Group g) const {
    for (const Aliasing& aliasing : aliases)
      if (aliasing.group == g)
        return aliasing;
    fail("aliasing not found");
  }

  /// @brief Parse group string to Group enum.
  /// @param str Group identifier string (e.g., "peptide", "P-peptide", "DNA").
  /// @return Parsed Group enum value, or Group::Null if unrecognized.
  static Group read_group(const std::string& str) {
    if (str.size() >= 3) {
      const char* cstr = str.c_str();
      if ((str[0] == '\'' || str[0] == '"') && str.size() >= 5)
        ++cstr;
      switch (ialpha4_id(cstr)) {
        case ialpha4_id("non-"): return Group::NonPolymer;
        case ialpha4_id("pept"): return Group::Peptide;
        case ialpha4_id("l-pe"): return Group::Peptide;
        case ialpha4_id("p-pe"): return Group::PPeptide;
        case ialpha4_id("m-pe"): return Group::MPeptide;
        case ialpha4_id("dna"):  return Group::Dna;
        case ialpha4_id("rna"):  return Group::Rna;
        case ialpha4_id("dna/"): return Group::DnaRna;
        case ialpha4_id("pyra"): return Group::Pyranose;
        case ialpha4_id("keto"): return Group::Ketopyranose;
        case ialpha4_id("fura"): return Group::Furanose;
      }
    }
    return Group::Null;
  }

  /// @brief Get string representation of a Group enum value.
  /// @param g Group enum value.
  /// @return String representation (e.g., "peptide", "P-peptide", "DNA", ".").
  static const char* group_str(Group g) {
    switch (g) {
      case Group::Peptide: return "peptide";
      case Group::PPeptide: return "P-peptide";
      case Group::MPeptide: return "M-peptide";
      case Group::Dna: return "DNA";
      case Group::Rna: return "RNA";
      case Group::DnaRna: return "DNA/RNA";
      case Group::Pyranose: return "pyranose";
      case Group::Ketopyranose: return "ketopyranose";
      case Group::Furanose: return "furanose";
      case Group::NonPolymer: return "non-polymer";
      case Group::Null: return ".";
    }
    unreachable();
  }

  /// @brief Set group from string and update parsed Group enum.
  /// @param s Group identifier string.
  void set_group(const std::string& s) {
    type_or_group = s;
    group = read_group(s);
  }

  /// @brief Find an atom by name.
  /// @param atom_id Atom name to search for.
  /// @return Iterator to the Atom, or atoms.end() if not found.
  std::vector<Atom>::iterator find_atom(const std::string& atom_id) {
    return std::find_if(atoms.begin(), atoms.end(),
                        [&](const Atom& a) { return a.id == atom_id; });
  }
  /// @brief Const version of find_atom().
  std::vector<Atom>::const_iterator find_atom(const std::string& atom_id) const {
    return const_cast<ChemComp*>(this)->find_atom(atom_id);
  }
  /// @brief Check if an atom with given name exists.
  /// @param atom_id Atom name to search for.
  /// @return True if atom exists.
  bool has_atom(const std::string& atom_id) const {
    return find_atom(atom_id) != atoms.end();
  }

  /// @brief Find an atom by legacy name.
  /// @param old_id Legacy atom name (old_id field).
  /// @return Iterator to the Atom, or atoms.end() if not found.
  std::vector<Atom>::iterator find_atom_by_old_name(const std::string& old_id) {
    return std::find_if(atoms.begin(), atoms.end(),
                        [&](const Atom& a) { return a.old_id == old_id; });
  }
  /// @brief Const version of find_atom_by_old_name().
  std::vector<Atom>::const_iterator find_atom_by_old_name(const std::string& old_id) const {
    return const_cast<ChemComp*>(this)->find_atom_by_old_name(old_id);
  }
  /// @brief Check if any atom has non-trivial legacy names.
  /// @return True if at least one atom has old_id set and different from id.
  bool has_old_names() const {
    return std::any_of(atoms.begin(), atoms.end(),
                       [&](const Atom& a) { return !a.old_id.empty() && a.old_id != a.id; });
  }

  /// @brief Get index of an atom by name (throw if not found).
  /// @param atom_id Atom name to search for.
  /// @return Zero-based index in atoms vector.
  /// @throws Calls fail() if atom is not found.
  int get_atom_index(const std::string& atom_id) const {
    auto it = find_atom(atom_id);
    if (it == atoms.end())
      fail("Chemical component ", name, " has no atom ", atom_id);
    return int(it - atoms.begin());
  }

  /// @brief Find index of an atom by name.
  /// @param atom_id Atom name to search for.
  /// @return Zero-based index in atoms vector, or -1 if not found.
  int find_atom_index(const std::string& atom_id) const {
    auto it = find_atom(atom_id);
    return it != atoms.end() ? int(it - atoms.begin()) : -1;
  }

  /// @brief Build a map of atom names to indices.
  /// @return Map from atom id to vector index.
  std::map<std::string, size_t> make_atom_index() const {
    std::map<std::string, size_t> atom_index;
    for (size_t i = 0; i < atoms.size(); ++i)
      atom_index[atoms[i].id] = i;
    return atom_index;
  }

  /// @brief Get an atom by name (throw if not found).
  /// @param atom_id Atom name to search for.
  /// @return Reference to the Atom.
  /// @throws Calls get_atom_index() which may call fail().
  const Atom& get_atom(const std::string& atom_id) const {
    return atoms[get_atom_index(atom_id)];
  }

  /// @brief Check if group is a peptide variant.
  /// @param g Group enum value.
  /// @return True if group is Peptide, PPeptide, or MPeptide.
  static bool is_peptide_group(Group g) {
    return g == Group::Peptide || g == Group::PPeptide || g == Group::MPeptide;
  }

  /// @brief Check if group is a nucleic acid variant.
  /// @param g Group enum value.
  /// @return True if group is Dna, Rna, or DnaRna.
  static bool is_nucleotide_group(Group g) {
    return g == Group::Dna || g == Group::Rna || g == Group::DnaRna;
  }

  /// @brief Remove restraints referring to absent atoms.
  /// Called after atoms have been removed to keep restraints consistent.
  void remove_nonmatching_restraints() {
    vector_remove_if(rt.bonds, [&](const Restraints::Bond& x) {
      return !has_atom(x.id1.atom) ||
             !has_atom(x.id2.atom);
    });
    vector_remove_if(rt.angles, [&](const Restraints::Angle& x) {
      return !has_atom(x.id1.atom) ||
             !has_atom(x.id2.atom) ||
             !has_atom(x.id3.atom);
    });
    vector_remove_if(rt.torsions, [&](const Restraints::Torsion& x) {
      return !has_atom(x.id1.atom) ||
             !has_atom(x.id2.atom) ||
             !has_atom(x.id3.atom) ||
             !has_atom(x.id4.atom);
    });
    vector_remove_if(rt.chirs, [&](const Restraints::Chirality& x) {
      return !has_atom(x.id_ctr.atom) ||
             !has_atom(x.id1.atom) ||
             !has_atom(x.id2.atom) ||
             !has_atom(x.id3.atom);
    });
    for (Restraints::Plane& plane : rt.planes)
      vector_remove_if(plane.ids, [&](const Restraints::AtomId& x) {
        return !has_atom(x.atom);
      });
  }

  /// @brief Remove all hydrogen atoms and update restraints.
  /// @return Reference to this ChemComp (for method chaining).
  ChemComp& remove_hydrogens() {
    vector_remove_if(atoms, [](const ChemComp::Atom& a) {
      return a.is_hydrogen();
    });
    remove_nonmatching_restraints();
    return *this;
  }
};

/// @brief Parse string to BondType enum.
/// @param s String representation (e.g., "single", "double", "aromatic", "deloc", "metal").
/// @return Parsed BondType, or Unspec for null or "coval".
/// @throws std::out_of_range for unexpected bond type strings.
inline BondType bond_type_from_string(const std::string& s) {
  if (s.size() >= 3)
    switch (ialpha4_id(s.c_str())) {
      case ialpha4_id("sing"): return BondType::Single;
      case ialpha4_id("doub"): return BondType::Double;
      case ialpha4_id("trip"): return BondType::Triple;
      case ialpha4_id("arom"): return BondType::Aromatic;
      case ialpha4_id("meta"): return BondType::Metal;
      case ialpha4_id("delo"): return BondType::Deloc;
      case ialpha4_id("1.5"):  return BondType::Deloc; // rarely used
      // program PDB2TNT produces a restraint file with bond type 'coval'
      case ialpha4_id("cova"):  return BondType::Unspec;
    }
  if (cif::is_null(s))
    return BondType::Unspec;
  throw std::out_of_range("Unexpected bond type: " + s);
}

/// @brief Convert BondType enum to string.
/// @param btype Bond type to convert.
/// @return String representation (".", "single", "double", "triple", "aromatic", "deloc", "metal").
inline const char* bond_type_to_string(BondType btype) {
  switch (btype) {
    case BondType::Unspec: return ".";
    case BondType::Single: return "single";
    case BondType::Double: return "double";
    case BondType::Triple: return "triple";
    case BondType::Aromatic: return "aromatic";
    case BondType::Deloc: return "deloc";
    case BondType::Metal: return "metal";
  }
  unreachable();
}

/// @brief Get bond order (multiplicity) for a BondType.
/// @param btype Bond type.
/// @return Bond order: 1.0 (single/metal), 1.5 (aromatic/deloc), 2.0 (double), 3.0 (triple), 0.0 (unspec).
inline float order_of_bond_type(BondType btype) {
  switch (btype) {
    case BondType::Single: return 1.0f;
    case BondType::Double: return 2.0f;
    case BondType::Triple: return 3.0f;
    case BondType::Aromatic: return 1.5f;
    case BondType::Deloc: return 1.5f;
    case BondType::Metal: return 1.0f;
    case BondType::Unspec: return 0.0f;
  }
  unreachable();
}

/// @brief Parse string to ChiralityType enum.
/// @param s String representation: "p" or "P" for Positive, "n" or "N" for Negative,
///   "b" or "B" or "." for Both.
/// @return Parsed ChiralityType.
/// @throws std::out_of_range for unexpected chirality strings (e.g., crossN types).
inline ChiralityType chirality_from_string(const std::string& s) {
  switch (s[0] | 0x20) {
    case 'p': return ChiralityType::Positive;
    case 'n': return ChiralityType::Negative;
    case 'b': return ChiralityType::Both;
    case '.': return ChiralityType::Both;
    default: throw std::out_of_range("Unexpected chirality: " + s);
  }
}

/// @brief Determine ChiralityType from stereo flag and computed chiral volume.
/// @param s Volume flag string: "s" or "S" (signed volume), "n" or "N" (no stereochemistry).
/// @param volume Computed chiral volume.
/// @return ChiralityType: Positive or Negative based on volume sign (if "s" flag),
///   or Both (if "n" flag).
/// @throws std::out_of_range for unexpected flag strings.
inline ChiralityType chirality_from_flag_and_volume(const std::string& s,
                                                    double volume) {
  switch (s[0] | 0x20) {
    case 's': return volume > 0 ? ChiralityType::Positive
                                : ChiralityType::Negative;
    case 'n': return ChiralityType::Both;
    default: throw std::out_of_range("Unexpected volume_flag: " + s);
  }
}

/// @brief Convert ChiralityType enum to string.
/// @param chir_type Chirality type.
/// @return String representation ("positive", "negative", "both").
inline const char* chirality_to_string(ChiralityType chir_type) {
  switch (chir_type) {
    case ChiralityType::Positive: return "positive";
    case ChiralityType::Negative: return "negative";
    case ChiralityType::Both: return "both";
  }
  unreachable();
}

/// @brief Parse a ChemComp from a CIF block.
/// Reads all _chem_comp* tables from the block (atoms, bonds, angles, torsions, chiralities, planes, aliases).
/// @param block_ CIF block containing chemical component definition.
/// @return Constructed ChemComp with all restraints and atom data.
inline ChemComp make_chemcomp_from_block(const cif::Block& block_) {
  ChemComp cc;
  cc.name = block_.name.substr(starts_with(block_.name, "comp_") ? 5 : 0);
  cif::Block& block = const_cast<cif::Block&>(block_);
  // CCD uses _chem_comp.type, monomer libraries use .group in a separate block
  // named comp_list, but it'd be a better idea to have _chem_comp.group in the
  // same block, so we try read it.
  if (cif::Column group_col = block.find_values("_chem_comp.group"))
    cc.set_group(group_col.str(0));
  else if (cif::Column type_col = block.find_values("_chem_comp.type"))
    cc.type_or_group = type_col.str(0);
  for (auto row : block.find("_chem_comp_atom.",
                             {"atom_id", "type_symbol", "?type_energy",
                             "?charge", "?partial_charge", "?alt_atom_id",
                             "?atom_type",
                             "?model_Cartn_x",
                             "?model_Cartn_y",
                             "?model_Cartn_z",
                             "?x",
                             "?y",
                             "?z",
                             "?pdbx_model_Cartn_x_ideal",
                             "?pdbx_model_Cartn_y_ideal",
                             "?pdbx_model_Cartn_z_ideal"})) {
    ChemComp::Atom atom;
    atom.id = row.str(0);
    atom.old_id = row.has(5) ? row.str(5) : "";
    atom.el = Element(row.str(1));
    atom.charge = (float) cif::as_number(row.one_of(3, 4), 0.0);
    atom.chem_type = row.has(2) ? row.str(2) : "";
    atom.acedrg_type = row.has(6) ? row.str(6) : "";
    auto set_xyz_if_finite = [&](int ix, int iy, int iz) {
      if (!row.has(ix) || !row.has(iy) || !row.has(iz))
        return false;
      double x = cif::as_number(row[ix]);
      double y = cif::as_number(row[iy]);
      double z = cif::as_number(row[iz]);
      if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z))
        return false;
      atom.xyz = Position(x, y, z);
      return true;
    };
    if (!set_xyz_if_finite(7, 8, 9) &&
        !set_xyz_if_finite(10, 11, 12))
      set_xyz_if_finite(13, 14, 15);
    cc.atoms.push_back(std::move(atom));
  }
  // Also check _chem_comp_acedrg table for atom types (used by acedrg output)
  for (auto row : block.find("_chem_comp_acedrg.", {"atom_id", "atom_type"})) {
    std::string atom_id = row.str(0);
    std::string atom_type = row.str(1);
    for (auto& atom : cc.atoms)
      if (atom.id == atom_id && atom.acedrg_type.empty()) {
        atom.acedrg_type = atom_type;
        break;
      }
  }
  for (auto row : block.find("_chem_comp_bond.",
                             {"atom_id_1", "atom_id_2",              // 0, 1
                              "?type", "?value_order",               // 2, 3
                              "?aromatic", "?pdbx_aromatic_flag",    // 4, 5
                              "?value_dist", "?value_dist_esd",      // 6, 7
                              "?value_dist_nucleus", "?value_dist_nucleus_esd"})) { // 8, 9
    bool aromatic_flag = (row.one_of(4, 5)[0] | 0x20) == 'y';
    double dist = row.has(6) ? cif::as_number(row[6]) : NAN;
    double esd = row.has(7) ? cif::as_number(row[7]) : NAN;
    double dist_nucl = row.has(8) ? cif::as_number(row[8]) : NAN;
    double esd_nucl = row.has(9) ? cif::as_number(row[9]) : NAN;
    BondType bt = bond_type_from_string(row.one_of(2, 3));
    cc.rt.bonds.push_back({{1, row.str(0)}, {1, row.str(1)},
                          bt,
                          aromatic_flag, dist, esd, dist_nucl, esd_nucl});
  }
  for (auto row : block.find("_chem_comp_angle.",
                             {"atom_id_1", "atom_id_2", "atom_id_3",
                              "value_angle", "value_angle_esd"}))
    cc.rt.angles.push_back({{1, row.str(0)}, {1, row.str(1)}, {1, row.str(2)},
                            cif::as_number(row[3]), cif::as_number(row[4])});
  for (auto row : block.find("_chem_comp_tor.",
                             {"id",
                              "atom_id_1", "atom_id_2",
                              "atom_id_3", "atom_id_4",
                              "value_angle", "value_angle_esd",
                              "period"}))
    cc.rt.torsions.push_back({row.str(0),
                              {1, row.str(1)}, {1, row.str(2)},
                              {1, row.str(3)}, {1, row.str(4)},
                              cif::as_number(row[5]), cif::as_number(row[6]),
                              cif::as_int(row[7])});
  for (auto row : block.find("_chem_comp_chir.",
                             {"atom_id_centre",
                              "atom_id_1", "atom_id_2", "atom_id_3",
                              "volume_sign"}))
    if (row[4][0] != 'c') // ignore crossN
      cc.rt.chirs.push_back({{1, row.str(0)},
                             {1, row.str(1)}, {1, row.str(2)}, {1, row.str(3)},
                             chirality_from_string(row[4])});
  // mmCIF compliant
  cif::Table chir_tab = block.find("_chem_comp_chir_atom.",
                                   {"chir_id", "atom_id"});
  if (chir_tab.ok()) {
    std::map<std::string, std::vector<std::string>> chir_atoms;
    for (auto chir : chir_tab)
      chir_atoms[chir[0]].push_back(chir[1]);
    for (auto row : block.find("_chem_comp_chir.",
                               {"id", "atom_id", "volume_flag", "volume_three"})) {
        auto atoms = chir_atoms.find(row.str(0));
        if (atoms != chir_atoms.end() && atoms->second.size() == 3)
          cc.rt.chirs.push_back({{1, row.str(1)},
                                 {1, atoms->second[0]}, {1, atoms->second[1]},
                                 {1, atoms->second[2]},
                                 chirality_from_flag_and_volume(row[2],
                                                                cif::as_number(row[3]))});
    }
  }
  for (auto row : block.find("_chem_comp_plane_atom.",
                             {"plane_id", "atom_id" , "dist_esd"})) {
    Restraints::Plane& plane = cc.rt.get_or_add_plane(row.str(0));
    if (plane.esd == 0.0)
      plane.esd = cif::as_number(row[2]);
    plane.ids.push_back({1, row.str(1)});
  }
  for (auto row : block.find("_chem_comp_alias.",
                             {"group", "atom_id", "atom_id_standard"})) {
    ChemComp::Group group = ChemComp::read_group(row.str(0));
    if (cc.aliases.empty() || cc.aliases.back().group != group) {
      cc.aliases.emplace_back();
      cc.aliases.back().group = group;
    }
    cc.aliases.back().related.emplace_back(row.str(1), row.str(2));
  }

  return cc;
}

} // namespace gemmi
#endif

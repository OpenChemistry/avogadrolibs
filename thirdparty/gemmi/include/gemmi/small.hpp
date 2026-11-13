/// @file
/// @brief Small molecule and inorganic crystal structures.
///
/// Flat-list representation of non-macromolecular structures (small molecules,
/// minerals, metal-organic frameworks). Contrast with hierarchical Structure
/// class (chains/residues/atoms) used for proteins/nucleic acids.

// Copyright 2018 Global Phasing Ltd.
//
// Representation of a small molecule or inorganic crystal.
// Flat list of atom sites. Minimal functionality.

#ifndef GEMMI_SMALL_HPP_
#define GEMMI_SMALL_HPP_

#include <cctype>        // for isalpha
#include <algorithm>     // for any_of
#include <bitset>
#include <string>
#include <vector>
#include "elem.hpp"      // Element
#include "math.hpp"      // SMat33
#include "symmetry.hpp"  // find_spacegroup_by_name
#include "unitcell.hpp"  // UnitCell, Fractional
#include "util.hpp"      // vector_remove_if

namespace gemmi {

/// @brief Check if point group operations form a complete mathematical group.
inline bool is_complete(const GroupOps& gops) {
  for (Op op1 : gops.sym_ops)
    for (Op op2 : gops.sym_ops)
      if (gops.find_by_rotation((op1 * op2).rot) == nullptr)
        return false;
  return true;
}

inline std::vector<Op> triplets_to_ops(const std::vector<std::string>& symops) {
  std::vector<Op> ops;
  ops.reserve(symops.size());
  for (const std::string& xyz : symops)
    ops.push_back(parse_triplet(xyz));
  return ops;
}

/// @brief Small molecule or inorganic crystal structure.
/// @details Flat-list representation of non-macromolecular structures with
/// unit cell and symmetry. Contrast with Structure class (chains/residues/atoms).
/// For CIF files describing minerals, small molecules, and MOFs.
struct SmallStructure {
  /// @brief Atom site in fractional coordinates.
  /// @details Corresponds to mmCIF _atom_site loop. Each site has element,
  /// occupancy, displacement parameters, and optional disorder grouping.
  struct Site {
    std::string label;              ///< Atom site label (e.g., "C1", "N1A")
    std::string type_symbol;        ///< Atom type for form-factor lookup
    Fractional fract;               ///< Fractional coordinates (0-1)
    double occ = 1.0;               ///< Occupancy (0-1, partial/disordered)
    double u_iso = 0.;              ///< Isotropic B-factor / Uiso
    SMat33<double> aniso = {};      ///< Anisotropic displacement parameters (Uij)
    int disorder_group = 0;         ///< Disorder group ID (0 = ordered site)
    Element element = El::X;        ///< Chemical element
    signed char charge = 0;         ///< Formal charge ([-8, +8])

    /// @brief Convert fractional to orthogonal (Cartesian) coordinates.
    /// @param cell_ Unit cell for coordinate transformation.
    /// @return Position in Ångströms.
    Position orth(const gemmi::UnitCell& cell_) const {
      return cell_.orthogonalize(fract);
    }

    /// @brief Format element and charge as string (e.g., "Na+", "S2-", "C").
    /// @return Element symbol optionally followed by charge.
    std::string element_and_charge_symbol() const {
      std::string s = element.name();
      if (charge != 0) {
        s += std::to_string(std::abs(charge));
        s += charge > 0 ? '+' : '-';
      }
      return s;
    }
  };

  /// @brief Atom type (for scattering factor lookups).
  /// @details Dispersion-corrected element type used in X-ray scattering
  /// calculations. Corresponds to mmCIF _atom_type category.
  struct AtomType {
    std::string symbol;             ///< Atom type label (e.g., "Ni2+", "C_sp2")
    Element element = El::X;        ///< Element without charge/hybridization
    signed char charge = 0;         ///< Formal charge
    double dispersion_real;         ///< Real anomalous scattering correction (Δf')
    double dispersion_imag;         ///< Imaginary anomalous scattering (Δf'')
  };

  std::string name;                           ///< Structure name/identifier
  UnitCell cell;                              ///< Unit cell parameters
  const SpaceGroup* spacegroup = nullptr;     ///< Space group (pointer to table)
  std::string spacegroup_hm;                  ///< Hermann-Mauguin symbol
  std::string spacegroup_hall;                ///< Hall symbol
  int spacegroup_number = 0;                  ///< ITC space group number (1-230)
  std::vector<std::string> symops;            ///< Symmetry operations (XYZ strings)
  std::vector<Site> sites;                    ///< Atom sites in asymmetric unit
  std::vector<AtomType> atom_types;           ///< Atom types for scattering factors
  double wavelength = 0.;                     ///< X-ray wavelength (Ångströms)

  /// @brief Get all atom sites including symmetry-generated copies.
  /// @return List of sites in full unit cell (and neighboring unit cells).
  /// @details Applies space group symmetry to asymmetric unit sites.
  std::vector<Site> get_all_unit_cell_sites() const;

  /// @brief Determine and assign space group from available data.
  /// @param order Preference order for source: 's'=symops, 'h'=Hall, '1'/'2'=H-M, 'n'=number.
  ///              Try in sequence until success. Pass nullptr to skip.
  /// @details Populates spacegroup pointer and cell image transformations.
  void determine_and_set_spacegroup(const char* order) {
    spacegroup = nullptr;
    if (order)
      for (const char* c = order; *c != '\0' && spacegroup == nullptr; ++c) {
        try {
          GroupOps gops;
          spacegroup = determine_spacegroup_from(*c, gops);
          if (!spacegroup && *(c+1) == '.') {
            // If symops don't correspond to tabulated settings,
            // we can't set spacegroup, but we can set UnitCell::images.
            if (gops.order() == (int) symops.size() && is_complete(gops)) {
              cell.set_cell_images_from_groupops(gops);
              return;
            }
            ++c;
          }
        } catch (std::exception&) {}
      }
    setup_cell_images();
  }

  /// @brief Determine space group from one data source.
  /// @param c Source selector: 's'=symops, 'h'=Hall, '1'=H-M setting 1, '2'=setting 2, 'n'=number.
  /// @param gops Output: group operations if successfully determined from symops.
  /// @return SpaceGroup pointer or nullptr if not found.
  /// @details Helper for determine_and_set_spacegroup(). Sets cell.images on success.
  const SpaceGroup* determine_spacegroup_from(char c, GroupOps& gops) const {
    switch (lower(c)) {
      case 's':
        if (symops.empty())
          return nullptr;
        gops = split_centering_vectors(triplets_to_ops(symops));
        return find_spacegroup_by_ops(gops);
      case 'h':
        if (spacegroup_hall.empty())
          return nullptr;
        return find_spacegroup_by_ops(symops_from_hall(spacegroup_hall.c_str()));
      case '1':
      case '2': {
        if (spacegroup_hm.empty())
          return nullptr;
        char prefer[] = {c, '\0'};
        return find_spacegroup_by_name(spacegroup_hm, cell.alpha, cell.gamma, prefer);
      }
      case 'n':
        if (spacegroup_number == 0)
          return nullptr;
        return find_spacegroup_by_number(spacegroup_number);
      default:
        throw std::invalid_argument("determine_and_set_spacegroup(): wrong character in 'order'");
    }
  }

  /// @brief Validate space group consistency.
  /// @return Error message string if inconsistencies found; empty string if valid.
  /// @details Checks symops, Hall symbol, H-M symbol, and spacegroup_number
  ///          for mutual consistency. Multiple sources can conflict.
  std::string check_spacegroup() const {
    std::string err;
    if (!symops.empty())
      try {
        std::vector<Op> ops = triplets_to_ops(symops);
        for (Op& op : ops)
          op.wrap();
        std::sort(ops.begin(), ops.end());
        GroupOps gops = split_centering_vectors(ops);
        if (!is_complete(gops))
          cat_to(err, "symops list is incomplete or incorrect\n");
        else if (gops.all_ops_sorted() != ops)
          cat_to(err, "symops list is incorrect or incomplete or redundant\n");
        const SpaceGroup* sg = find_spacegroup_by_ops(gops);
        if (!sg)
          cat_to(err, "space group from symops not found in the table\n");
        else if (sg != spacegroup)
          cat_to(err, "space group from symops differs: ", sg->xhm(), '\n');
      } catch (std::exception& e) {
        cat_to(err, "error while processing symops: ", e.what(), '\n');
      }
    if (!spacegroup_hall.empty())
      try {
        const SpaceGroup* sg = find_spacegroup_by_ops(symops_from_hall(spacegroup_hall.c_str()));
        if (!sg)
          cat_to(err, "space group from Hall symbol (", spacegroup_hall,
                 ") not found in the table\n");
        else if (spacegroup != sg)
          cat_to(err, "space group from Hall symbol (", spacegroup_hall,
                 ") differs: ", sg->xhm(), '\n');
      } catch (std::exception& e) {
        cat_to(err, "error while processing Hall symbol: ", e.what(), '\n');
      }
    if (!spacegroup_hm.empty()) {
      const SpaceGroup* sg = find_spacegroup_by_name(spacegroup_hm, cell.alpha, cell.gamma, "2");
      if (!sg)
        cat_to(err, "H-M symbol (", spacegroup_hm, ") not found in the table\n");
      else if (!spacegroup || strcmp(spacegroup->hm, sg->hm) != 0)
        cat_to(err, "space group from H-M symbol (", spacegroup_hm,
               ") differs: ", sg->hm, '\n');
    }
    if (spacegroup_number != 0 && spacegroup && spacegroup->number != spacegroup_number)
      cat_to(err, "space group number (", spacegroup_number, ") differs\n");
    return err;
  }

  /// @brief Look up atom type by symbol.
  /// @param symbol Atom type label (e.g., "C1", "Ni2+").
  /// @return Pointer to matching AtomType, or nullptr if not found.
  const AtomType* get_atom_type(const std::string& symbol) const {
    for (const AtomType& at : atom_types)
      if (at.symbol == symbol)
        return &at;
    return nullptr;
  }

  /// @brief Get bitset of elements present in structure.
  /// @return Bitset where bit i is set if element El(i) appears in sites.
  /// @details Similar to Model::present_elements() in the macromolecular API.
  std::bitset<(size_t)El::END> present_elements() const {
    std::bitset<(size_t)El::END> table;
    for (const Site& atom : sites)
      table.set((size_t)atom.element.elem);
    return table;
  }

  /// @brief Remove all hydrogen atoms from structure.
  /// @details Modifies sites vector in-place.
  void remove_hydrogens() {
    vector_remove_if(sites, [](const Site& a) { return a.element.is_hydrogen(); });
  }

  /// @brief Convert occupancies from chemical to crystallographic convention.
  /// @param max_dist Distance tolerance for identifying special positions (Å).
  /// @details Precondition: occupancies are given in chemical convention
  ///          (i.e., sum to 1 when all symmetry copies are included, not divided
  ///          by multiplicity). Divides occupancies by (n_mates+1) for sites
  ///          on special positions, where n_mates is symmetry multiplicity.
  void change_occupancies_to_crystallographic(double max_dist=0.4) {
    for (Site& site : sites) {
      int n_mates = cell.is_special_position(site.fract, max_dist);
      if (n_mates != 0)
        site.occ /= (n_mates + 1);
    }
  }

  /// @brief Configure cell images from assigned space group.
  /// @details Sets cell.images transformations based on spacegroup.
  ///          Call after determine_and_set_spacegroup() or when spacegroup
  ///          is manually assigned.
  void setup_cell_images() {
    cell.set_cell_images_from_spacegroup(spacegroup);
  }
};

/// @brief Parse element and charge from atom type label.
/// @tparam T Type with element and charge members (e.g., Site, AtomType).
/// @param label Atom type label (e.g., "C", "Na+", "S2-", "Ni2+").
/// @param dest Pointer to destination object (sets dest->element, dest->charge).
/// @details Extracts element symbol (1-2 chars) and optional charge.
///          Charge is at end: "+", "-", "+2", "-2", etc.
template<typename T>
inline void split_element_and_charge(const std::string& label, T* dest) {
  int len = label.size() > 1 && std::isalpha(label[1]) ? 2 : 1;
  dest->element = len == 1 ? impl::find_single_letter_element(label[0] & ~0x20)
                           : find_element(label.c_str());
  if (dest->element != El::X && (label.back() == '+' || label.back() == '-')) {
    int sign = label.back() == '+' ? 1 : -1;
    if (label.size() - len == 1)
      dest->charge = sign;
    else if (label.size() - len == 2 && label[len] >= '0' && label[len] <= '9')
      dest->charge = sign * (label[len] - '0');
  }
}

/// @brief Generate all unit cell sites from asymmetric unit and symmetry.
/// @return Vector of sites in full unit cell (and neighboring cells if needed).
/// @details Applies space group symmetry operations and translational symmetry
///          (cell.images) to generate all symmetry-equivalent copies. Avoids
///          duplicate sites within special position tolerance (0.4 Å).
inline std::vector<SmallStructure::Site>
SmallStructure::get_all_unit_cell_sites() const {
  const double SPECIAL_POS_TOL = 0.4;
  std::vector<Site> all;
  for (const Site& site : sites) {
    size_t start = all.size();
    all.push_back(site);
    for (const FTransform& image : cell.images) {
      Fractional fpos = image.apply(site.fract);
      if (std::any_of(all.begin() + start, all.end(), [&](const Site& other) {
            return cell.distance_sq(fpos, other.fract) < sq(SPECIAL_POS_TOL);
          }))
        continue;
      all.push_back(site);
      all.back().fract = fpos;
    }
  }
  return all;
}

} // namespace gemmi
#endif

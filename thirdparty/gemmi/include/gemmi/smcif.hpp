/// @file
/// @brief Reading and writing small-molecule CIF files into SmallStructure format.
///
/// Copyright 2018 Global Phasing Ltd.
///
/// Provides functions to parse CIF (Crystallographic Information File) blocks
/// into Gemmi's SmallStructure representation for small molecules, ligands,
/// and inorganic crystals. Handles fractional coordinates, anisotropic
/// displacement parameters, and symmetry operations.

#ifndef GEMMI_SMCIF_HPP_
#define GEMMI_SMCIF_HPP_

#include "small.hpp"     // for SmallStructure
#include "cifdoc.hpp"
#include "numb.hpp"      // for as_number
#include "sprintf.hpp"   // for to_str

namespace gemmi {

/// @brief Parses a CIF block into a SmallStructure object.
/// @param block_ CIF block to parse.
/// @return SmallStructure containing atomic positions, symmetry, and cell parameters.
/// Extracts unit cell parameters, space group information (H-M and Hall symbols,
/// international tables number), symmetry operations, atom sites with fractional
/// coordinates (occupancy, anisotropic displacement), anisotropic temperature
/// factors (_atom_site_aniso_*), atom types with dispersion corrections, and
/// radiation wavelength. Coordinates are assumed to be fractional (CIF convention).
inline
SmallStructure make_small_structure_from_block(const cif::Block& block_) {
  using cif::as_number;
  cif::Block& block = const_cast<cif::Block&>(block_);
  SmallStructure st;
  st.name = block.name;

  // unit cell and symmetry
  cif::Table cell = block.find("_cell_",
                               {"length_a", "length_b", "length_c",
                                "angle_alpha", "angle_beta", "angle_gamma"});
  if (cell.ok()) {
    auto c = cell.one();
    if (!cif::is_null(c[0]) && !cif::is_null(c[1]) && !cif::is_null(c[2]))
      st.cell.set(as_number(c[0]), as_number(c[1]), as_number(c[2]),
                  as_number(c[3]), as_number(c[4]), as_number(c[5]));
  }
  for (const char* tag : {"_space_group_name_H-M_alt",
                          "_symmetry_space_group_name_H-M"})
    if (const std::string* val = block.find_value(tag)) {
      st.spacegroup_hm = cif::as_string(*val);
      break;
    }
  for (const char* tag : {"_space_group_symop_operation_xyz",
                          "_symmetry_equiv_pos_as_xyz"}) {
    if (const cif::Column col = block.find_values(tag)) {
      st.symops.reserve(col.length());
      for (const std::string& value : col)
        st.symops.push_back(cif::as_string(value));
      break;
    }
  }
  for (const char* tag : {"_space_group_name_Hall", "_symmetry_space_group_name_Hall"})
    if (const std::string* val = block.find_value(tag))
      st.spacegroup_hall = cif::as_string(*val);
  for (const char* tag : {"_space_group_IT_number", "_symmetry_Int_Tables_number"})
    if (const std::string* val = block.find_value(tag)) {
      st.spacegroup_number = cif::as_int(*val, 0);
      break;
    }
  st.determine_and_set_spacegroup("S.H2");

  enum { kLabel, kSymbol, kX, kY, kZ, kUiso, kBiso, kOcc, kDisorderGroup };
  cif::Table atom_table = block.find("_atom_site_",
                                     {"label",
                                      "?type_symbol",
                                      "?fract_x",
                                      "?fract_y",
                                      "?fract_z",
                                      "?U_iso_or_equiv",
                                      "?B_iso_or_equiv",
                                      "?occupancy",
                                      "?disorder_group"});
  for (auto row : atom_table) {
    SmallStructure::Site site;
    site.label = cif::as_string(row[kLabel]);
    if (row.has(kSymbol))
      site.type_symbol = cif::as_string(row[kSymbol]);
    else
      site.type_symbol = site.label;
    if (row.has(kX))
      site.fract.x = as_number(row[kX]);
    if (row.has(kY))
      site.fract.y = as_number(row[kY]);
    if (row.has(kZ))
      site.fract.z = as_number(row[kZ]);
    if (row.has(kUiso))
      site.u_iso = as_number(row[kUiso], 0.0);
    else if (row.has(kBiso))
      site.u_iso = as_number(row[kBiso], 0.0) / u_to_b();
    if (row.has(kOcc))
      site.occ = as_number(row[kOcc], 1.0);
    if (row.has2(kDisorderGroup))
      // ignore non-integer _atom_site_disorder_group
      site.disorder_group = string_to_int(row[kDisorderGroup], false);
    split_element_and_charge(site.type_symbol, &site);
    st.sites.push_back(site);
  }

  std::vector<SmallStructure::Site>::iterator aniso_site = st.sites.begin();
  for (auto row : block.find("_atom_site_aniso_",
                             {"label", "U_11", "U_22", "U_33",
                              "U_12", "U_13", "U_23"})) {
    std::string aniso_label = row.str(0);
    if (aniso_site == st.sites.end() || aniso_site->label != aniso_label) {
      aniso_site = std::find_if(st.sites.begin(), st.sites.end(),
              [&](SmallStructure::Site& x) { return x.label == aniso_label; });
      if (aniso_site == st.sites.end())
        continue;
    }
    aniso_site->aniso.u11 = as_number(row[1], 0.0);
    aniso_site->aniso.u22 = as_number(row[2], 0.0);
    aniso_site->aniso.u33 = as_number(row[3], 0.0);
    aniso_site->aniso.u12 = as_number(row[4], 0.0);
    aniso_site->aniso.u13 = as_number(row[5], 0.0);
    aniso_site->aniso.u23 = as_number(row[6], 0.0);
    ++aniso_site;
  }

  for (auto row : block.find("_atom_type_",
                             {"symbol",
                              "scat_dispersion_real",
                              "scat_dispersion_imag"})) {
    SmallStructure::AtomType atom_type;
    atom_type.symbol = row.str(0);
    atom_type.dispersion_real = cif::as_number(row[1]);
    atom_type.dispersion_imag = cif::as_number(row[2]);
    split_element_and_charge(atom_type.symbol, &atom_type);
    st.atom_types.push_back(atom_type);
  }
  if (cif::Column w_col = block.find_values("_diffrn_radiation_wavelength"))
    st.wavelength = cif::as_number(w_col.at(0));
  return st;
}

/// @brief Converts a SmallStructure into a CIF block.
/// @param st SmallStructure to convert.
/// @return CIF block with cell parameters, symmetry, and atom sites.
/// Generates CIF representation with crystallographic cell, space group name,
/// atom site loop (_atom_site_*), anisotropic displacement loop
/// (_atom_site_aniso_*), and radiation wavelength if non-zero.
/// Uses fractional coordinates (CIF convention).
inline cif::Block make_cif_block_from_small_structure(const SmallStructure& st) {
  cif::Block block;
  block.name = st.name;
  if (st.cell.is_crystal()) {
    block.set_pair("_cell_length_a", to_str(st.cell.a));
    block.set_pair("_cell_length_b", to_str(st.cell.b));
    block.set_pair("_cell_length_c", to_str(st.cell.c));
    block.set_pair("_cell_angle_alpha", to_str(st.cell.alpha));
    block.set_pair("_cell_angle_beta", to_str(st.cell.beta));
    block.set_pair("_cell_angle_gamma", to_str(st.cell.gamma));
  }
  if (!st.spacegroup_hm.empty())
    block.set_pair("_symmetry_space_group_name_H-M", cif::quote(st.spacegroup_hm));
  if (st.wavelength != 0)
    block.set_pair("_diffrn_radiation_wavelength", to_str(st.wavelength));

  cif::Loop& atom_loop = block.init_loop("_atom_site_", {"label",
                                                         "type_symbol",
                                                         "fract_x",
                                                         "fract_y",
                                                         "fract_z",
                                                         "U_iso_or_equiv",
                                                         "occupancy",
                                                         "disorder_group"});
  for (const SmallStructure::Site& site: st.sites) {
    atom_loop.add_row({
        cif::quote(site.label),
        site.type_symbol.empty() ? site.element_and_charge_symbol()
                                 : cif::quote(site.type_symbol),
        to_str(site.fract.x),
        to_str(site.fract.y),
        to_str(site.fract.z),
        to_str(site.u_iso),
        to_str(site.occ),
        site.disorder_group == 0 ? "." : std::to_string(site.disorder_group)
    });
  }

  bool has_aniso = false;
  for (const SmallStructure::Site& site: st.sites)
    if (site.aniso.nonzero()) {
      has_aniso = true;
      break;
    }
  if (has_aniso) {
    cif::Loop& aniso_loop = block.init_loop("_atom_site_aniso_", {
        "label", "U_11", "U_22", "U_33", "U_12", "U_13", "U_23"});
    for (const SmallStructure::Site& site: st.sites)
      if (site.aniso.nonzero())
        aniso_loop.add_row({
            cif::quote(site.label),
            to_str(site.aniso.u11), to_str(site.aniso.u22), to_str(site.aniso.u33),
            to_str(site.aniso.u12), to_str(site.aniso.u13), to_str(site.aniso.u23)
        });
  }

  return block;
}

} // namespace gemmi
#endif

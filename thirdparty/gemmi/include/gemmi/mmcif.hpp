/// @file
/// @brief Read mmCIF (PDBx/mmCIF) coordinate files into a Structure.

// Copyright 2017 Global Phasing Ltd.
//
// Read mmCIF (PDBx/mmCIF) file into a Structure from model.hpp.

#ifndef GEMMI_MMCIF_HPP_
#define GEMMI_MMCIF_HPP_

#include <string>
#include "cifdoc.hpp"      // for Block, etc
#include "fail.hpp"        // for fail
#include "model.hpp"       // for Structure

namespace gemmi {

/// Populate Structure by parsing a coordinate mmCIF block.
/// @param block_ A CIF block containing the coordinate data (typically from
///               an mmCIF file, containing _atom_site categories)
/// @param st     The Structure to populate with coordinates, cell parameters,
///               and other crystallographic data
/// @throws Throws on parse errors or invalid coordinate data
GEMMI_DLL void populate_structure_from_block(const cif::Block& block_, Structure& st);

/// Build a Structure by parsing a coordinate mmCIF block.
/// Convenience wrapper around populate_structure_from_block().
/// @param block_ A CIF block containing the coordinate data
/// @return A new Structure populated from the block
inline Structure make_structure_from_block(const cif::Block& block_) {
  gemmi::Structure st;
  populate_structure_from_block(block_, st);
  return st;
}

/// Build a Structure from a parsed mmCIF document.
/// Parses the first block (coordinate block) and validates that only
/// the first block contains atomic coordinates.
/// @param doc      A CIF document (typically mmCIF); moved into this function
/// @param save_doc Optional pointer to receive the parsed document (moved into *save_doc)
/// @return A Structure populated from the first block of the document
/// @throws Throws if multiple blocks contain atomic coordinates (_atom_site)
inline Structure make_structure(cif::Document&& doc, cif::Document* save_doc=nullptr) {
  // mmCIF files for deposition may have more than one block:
  // coordinates in the first block and restraints in the others.
  for (size_t i = 1; i < doc.blocks.size(); ++i)
    if (doc.blocks[i].has_tag("_atom_site.id"))
      fail("2+ blocks are ok if only the first one has coordinates;\n"
           "_atom_site in block #" + std::to_string(i+1) + ": " + doc.source);
  Structure st = make_structure_from_block(doc.blocks.at(0));
  if (save_doc)
    *save_doc = std::move(doc);
  return st;
}

/// @brief Selects which coordinate model(s) to read from chemical component files.
/// Used when reading CCD (Chemical Component Dictionary) or monomer library entries.
enum class ChemCompModel {
  Xyz      = 1, ///< Cartesian coordinates from _chem_comp_atom.x/y/z fields
  Example  = 2, ///< Example model coordinates from _chem_comp_atom.model_Cartn_x/y/z
  Ideal    = 4, ///< Ideal coordinates from _chem_comp_atom.pdbx_model_Cartn_x/y/z_ideal
  First    = 8  ///< Whichever coordinate set appears first in the input file
};

constexpr int operator|(ChemCompModel a, ChemCompModel b) { return (int)a | (int)b; }

/// Extract a Residue from a chemical component block.
/// Reads atom coordinates and bond information from a CCD or monomer library block.
/// @param block The CIF block containing chemical component data
/// @param kind  Which coordinate model to extract (Xyz, Example, Ideal, or First)
/// @return A Residue with atoms positioned according to the selected model
GEMMI_DLL Residue make_residue_from_chemcomp_block(const cif::Block& block, ChemCompModel kind);

/// Build a single-residue Model from a chemical component block.
/// Convenience wrapper that creates a Model with an unnamed chain
/// containing a single Residue extracted from the block.
/// @param block The CIF block containing chemical component data
/// @param kind  Which coordinate model to extract
/// @return A Model with one empty chain containing one Residue
inline Model make_model_from_chemcomp_block(const cif::Block& block, ChemCompModel kind) {
  Model model;
  model.chains.emplace_back("");
  model.chains[0].residues.push_back(make_residue_from_chemcomp_block(block, kind));
  return model;
}

/// Build a Structure from a chemical component block.
/// For CCD input, generates a structure with multiple single-residue models
/// (xyz, example, and/or ideal coordinates as requested).
/// For Refmac monomer library (dictionary) files, generates a single model.
/// The structure's input_format is set to CoorFormat::ChemComp.
/// @param block Which CIF block to parse (typically the chemical component block)
/// @param which Bitmask of ChemCompModel values to include; default 7 = Xyz|Example|Ideal
/// @return A Structure containing the requested coordinate models
inline Structure make_structure_from_chemcomp_block(const cif::Block& block, int which=7) {
  Structure st;
  st.input_format = CoorFormat::ChemComp;
  if (const std::string* name = block.find_value("_chem_comp.id"))
    st.name = *name;
  auto ok = [which](ChemCompModel x) { return which & static_cast<int>(x); };
  if (ok(ChemCompModel::Xyz) && block.has_any_value("_chem_comp_atom.x"))
    st.models.push_back(make_model_from_chemcomp_block(block, ChemCompModel::Xyz));
  if (ok(ChemCompModel::Example) && block.has_any_value("_chem_comp_atom.model_Cartn_x"))
    st.models.push_back(make_model_from_chemcomp_block(block, ChemCompModel::Example));
  if (ok(ChemCompModel::Ideal) && block.has_any_value("_chem_comp_atom.pdbx_model_Cartn_x_ideal"))
    st.models.push_back(make_model_from_chemcomp_block(block, ChemCompModel::Ideal));
  st.renumber_models();
  return st;
}

/// Identify which block in a document contains chemical component data.
/// Helper for make_structure_from_chemcomp_block(); distinguishes between
/// three file formats: monomer library with/without global block, and CCD files.
/// Example usage:
/// @code
/// int n = check_chemcomp_block_number(doc);
/// if (n != -1)
///   Structure st = make_structure_from_chemcomp_block(doc.blocks[n]);
/// @endcode
/// @param doc A parsed CIF document
/// @return Block index (0, 1, or 2) if recognized as chemical component file;
///         -1 if not a recognized chemical component format
inline int check_chemcomp_block_number(const cif::Document& doc) {
  // monomer library file without global_
  if (doc.blocks.size() == 2 && doc.blocks[0].name == "comp_list")
    return 1;
  // monomer library file with global_
  if (doc.blocks.size() == 3 && doc.blocks[0].name.empty() &&
      doc.blocks[1].name == "comp_list")
    return 2;
  // CCD file
  if (doc.blocks.size() == 1 &&
      !doc.blocks[0].has_tag("_atom_site.id") &&
      !doc.blocks[0].has_tag("_cell.length_a") &&
      doc.blocks[0].has_tag("_chem_comp_atom.atom_id"))
    return 0;
  return -1;
}

/// Build a Structure from a chemical component document.
/// Automatically detects and parses the appropriate block in a chemical
/// component file (CCD, monomer library with/without global block).
/// @param doc      A parsed chemical component CIF document
/// @param save_doc Optional pointer to receive the parsed document (moved into *save_doc)
/// @param which    Bitmask of ChemCompModel values to include; default 7 = all
/// @return A Structure with the requested coordinate models
/// @throws Throws if the document is not a recognized chemical component format
inline Structure make_structure_from_chemcomp_doc(const cif::Document& doc,
                                                  cif::Document* save_doc=nullptr,
                                                  int which=7) {
  int n = check_chemcomp_block_number(doc);
  if (n == -1)
    fail("Not a chem_comp format.");
  Structure st = make_structure_from_chemcomp_block(doc.blocks[n], which);
  if (save_doc)
    *save_doc = std::move(doc);
  return st;
}

} // namespace gemmi
#endif

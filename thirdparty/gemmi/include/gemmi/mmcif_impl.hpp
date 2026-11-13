// Copyright 2019 Global Phasing Ltd.
//
// Functions used in both mmcif.hpp and refln.hpp (for coordinate and
// reflection mmCIF files).

#ifndef GEMMI_MMCIF_IMPL_HPP_
#define GEMMI_MMCIF_IMPL_HPP_

#include "cifdoc.hpp"    // for cif::Block
#include "numb.hpp"      // for cif::as_number
#include "unitcell.hpp"  // for UnitCell

namespace gemmi {
namespace impl {

/// @brief Populate a UnitCell from _cell.* tags in a CIF block.
/// @param block The CIF block to read from.
/// @param cell Output — set from the CIF data.
/// @param mmcif If true use "_cell." prefix, else use "_cell_" for legacy PDB CIF style.
inline void set_cell_from_mmcif(cif::Block& block, UnitCell& cell,
                                bool mmcif=true) {
  cif::Table tab = block.find((mmcif ? "_cell." : "_cell_"),
                              {"length_a", "length_b", "length_c",
                               "angle_alpha", "angle_beta", "angle_gamma"});
  if (tab.ok()) {
    auto c = tab.one();
    if (!cif::is_null(c[0]) && !cif::is_null(c[1]) && !cif::is_null(c[2]))
      cell.set(cif::as_number(c[0]), cif::as_number(c[1]), cif::as_number(c[2]),
               cif::as_number(c[3]), cif::as_number(c[4]), cif::as_number(c[5]));
  }
}

/// @brief Return pointer to the _symmetry.space_group_name_H-M value in the block.
/// @param block The CIF block to search.
/// @return Pointer to the H-M space group name string, or nullptr if absent.
inline const std::string* find_spacegroup_hm_value(const cif::Block& block) {
  const char* hm_tag = "_symmetry.space_group_name_H-M";
  return block.find_value(hm_tag);
}

} // namespace impl
} // namespace gemmi

#endif

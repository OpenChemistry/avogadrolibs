/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// Checks that the bundled gemmi library links and reads one file of each kind
// we plan to use it for: small-molecule CIF, mmCIF, CCP4 maps and MTZ.

#include <gtest/gtest.h>

#include "iotests.h"

#include <gemmi/calculate.hpp>
#include <gemmi/ccp4.hpp>
#include <gemmi/cif.hpp>
#include <gemmi/fourier.hpp>
#include <gemmi/mmcif.hpp>
#include <gemmi/mtz.hpp>
#include <gemmi/smcif.hpp>

#include <exception>
#include <string>
#include <utility>

namespace cif = gemmi::cif;

namespace {
std::string dataPath(const char* relative)
{
  return std::string(AVOGADRO_DATA) + "/data/" + relative;
}
} // namespace

TEST(GemmiTest, smallMoleculeCif)
{
  try {
    cif::Document doc = cif::read_file(dataPath("cif/2017715.cif"));
    cif::Block& block = doc.sole_block();
    gemmi::SmallStructure structure =
      gemmi::make_small_structure_from_block(block);

    EXPECT_EQ(structure.sites.size(), 90u);
    ASSERT_NE(structure.spacegroup, nullptr);
    EXPECT_EQ(structure.spacegroup->xhm(), "P 21 21 21");

    size_t partial = 0;
    for (const auto& site : structure.sites) {
      if (site.occ < 0.999)
        ++partial;
    }
    EXPECT_EQ(partial, 21u);

    // gemmi's SmallStructure ignores this column, so read it from the block.
    cif::Column assembly = block.find_values("_atom_site_disorder_assembly");
    ASSERT_TRUE(assembly);
    size_t nonNull = 0;
    for (const std::string& value : assembly) {
      if (!cif::is_null(value))
        ++nonNull;
    }
    EXPECT_EQ(nonNull, 30u);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiTest, mmCif)
{
  try {
    cif::Document doc = cif::read_file(dataPath("gemmi/5i55.cif"));
    gemmi::Structure structure = gemmi::make_structure(std::move(doc));

    ASSERT_EQ(structure.models.size(), 1u);
    EXPECT_EQ(gemmi::count_atom_sites(structure.models[0]), 218u);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiTest, ccp4Map)
{
  try {
    gemmi::Ccp4<float> map;
    map.read_ccp4_file(dataPath("gemmi/5i55_tiny.ccp4"));

    EXPECT_EQ(map.grid.nu, 8);
    EXPECT_EQ(map.grid.nv, 6);
    EXPECT_EQ(map.grid.nw, 10);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiTest, mtzMap)
{
  try {
    gemmi::Mtz mtz;
    mtz.read_file(dataPath("gemmi/5wkd_phases.mtz"));

    const gemmi::Mtz::Column* amplitude = mtz.column_with_label("FWT");
    const gemmi::Mtz::Column* phase = mtz.column_with_label("PHWT");
    ASSERT_NE(amplitude, nullptr);
    ASSERT_NE(phase, nullptr);

    auto grid = gemmi::transform_f_phi_to_map2<float>(
      gemmi::FPhiProxy<gemmi::MtzDataProxy>(gemmi::MtzDataProxy{ mtz },
                                            amplitude->idx, phase->idx),
      { 0, 0, 0 }, 3.0, { 0, 0, 0 });

    EXPECT_EQ(grid.nu, 90);
    EXPECT_EQ(grid.nv, 8);
    EXPECT_EQ(grid.nw, 30);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

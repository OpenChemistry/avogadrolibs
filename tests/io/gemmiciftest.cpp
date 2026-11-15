/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <gemmi/cif.hpp>

#include <set>
#include <stdexcept>
#include <string>

namespace cif = gemmi::cif;

TEST(GemmiCifTest, smallMoleculeCif)
{
  try {
    cif::Document doc = cif::read_file(AVOGADRO_DATA "/data/cif/2017715.cif");
    ASSERT_EQ(doc.blocks.size(), 1u);
    cif::Block& block = doc.sole_block();

    const std::string* a = block.find_value("_cell_length_a");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(*a, "4.7855(4)");

    cif::Table atoms =
      block.find("_atom_site_", { "label", "?occupancy", "?disorder_assembly",
                                  "?disorder_group" });
    ASSERT_TRUE(atoms.ok());
    EXPECT_EQ(atoms.length(), 90u);

    size_t withAssembly = 0;
    std::set<std::string> assemblies;
    for (auto row : atoms) {
      if (row.has(2) && !cif::is_null(row[2])) {
        ++withAssembly;
        assemblies.insert(row[2]);
      }
    }
    EXPECT_EQ(withAssembly, 30u);
    EXPECT_EQ(assemblies, (std::set<std::string>{ "A", "B", "C" }));

    cif::Column bonds = block.find_values("_geom_bond_atom_site_label_1");
    ASSERT_NE(bonds.item(), nullptr);
    EXPECT_EQ(bonds.length(), 81u);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiCifTest, optionalLookupsDoNotThrow)
{
  try {
    cif::Document doc = cif::read_file(AVOGADRO_DATA "/data/cif/2017715.cif");
    cif::Block& block = doc.sole_block();

    EXPECT_EQ(block.find_value("_no_such_tag"), nullptr);

    cif::Table table =
      block.find("_atom_site_", { "label", "?no_such_column" });
    ASSERT_TRUE(table.ok());
    ASSERT_GT(table.length(), 0u);
    for (auto row : table) {
      EXPECT_TRUE(row.has(0));
      EXPECT_FALSE(row.has(1));
    }

    // A required tag that is missing yields an empty table, not an exception.
    EXPECT_FALSE(block.find("_no_such_prefix_", { "x" }).ok());
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiCifTest, mmcifTokenizes)
{
  try {
    cif::Document doc = cif::read_file(AVOGADRO_DATA "/data/gemmi/5i55.cif");
    cif::Block& block = doc.sole_block();
    cif::Table atoms =
      block.find("_atom_site.", { "group_PDB", "type_symbol", "Cartn_x" });
    ASSERT_TRUE(atoms.ok());
    EXPECT_EQ(atoms.length(), 218u);
  } catch (const std::exception& e) {
    FAIL() << e.what();
  }
}

TEST(GemmiCifTest, malformedInputThrows)
{
  const std::string unterminated = "data_x\n_tag 'unterminated\n";
  EXPECT_THROW(
    cif::read_memory(unterminated.data(), unterminated.size(), "bad1"),
    std::runtime_error);

  const std::string wrongCount = "data_x\nloop_\n_a\n_b\n1 2\n3\n";
  EXPECT_THROW(cif::read_memory(wrongCount.data(), wrongCount.size(), "bad2"),
               std::runtime_error);
}

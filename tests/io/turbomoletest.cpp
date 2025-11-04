/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/turbomoleformat.h>

#include <string>

using Avogadro::ANGSTROM_TO_BOHR;
using Avogadro::BOHR_TO_ANGSTROM;
using Avogadro::Vector3;
using Avogadro::Core::Molecule;
using Avogadro::Io::TurbomoleFormat;
using namespace std::string_literals;

TEST(TurbomoleTest, readNonPeriodic)
{
  TurbomoleFormat tmol;
  Molecule molecule;
  const auto str = R"(# $cell is commented out
# $cell
# 8.0 8.0 8.0 90.0 90.0 90.0
# $end
$coord
-1.000  2.000  4.000  h
 1.568  2.000  4.000  cl f # Fixed
$end
)"s;
  EXPECT_TRUE(tmol.readString(str, molecule)) << str << '\n' << tmol.error();
  const auto* const uc = molecule.unitCell();
  EXPECT_EQ(uc, nullptr) << str << uc->cellMatrix();
  ASSERT_EQ(molecule.atomCount(), 2u) << str;
  {
    const auto& atom = molecule.atom(0);
    EXPECT_EQ(atom.atomicNumber(), 1u);
    EXPECT_EQ(atom.position3d().x() / BOHR_TO_ANGSTROM, -1.0);
    EXPECT_EQ(atom.position3d().y() / BOHR_TO_ANGSTROM, 2.0);
    EXPECT_EQ(atom.position3d().z() / BOHR_TO_ANGSTROM, 4.0);
  }
  {
    const auto& atom = molecule.atom(1);
    EXPECT_EQ(atom.atomicNumber(), 17u);
    EXPECT_EQ(atom.position3d().x() / BOHR_TO_ANGSTROM, 1.568);
    EXPECT_EQ(atom.position3d().y() / BOHR_TO_ANGSTROM, 2.0);
    EXPECT_EQ(atom.position3d().z() / BOHR_TO_ANGSTROM, 4.0);
  }
}

TEST(TurbomoleTest, readCellParameters)
{
  auto cell = [](unsigned periodic, const std::string& extra = "") {
    const std::map<unsigned, std::string> CELLS = {
      { 1, "6.0"s },
      { 2, "6.0 8.0 90.0"s },
      { 3, "6.0 8.0 10.0 90.0 90.0 90.0"s }
    };
    return "$cell"s + extra + '\n' + CELLS.at(periodic) + '\n';
  };

  auto lattice = [](unsigned periodic, const std::string& extra = "") {
    std::map<unsigned, std::string> LATTICES = {
      { 1, "6.0"s },
      { 2, "6.0 0.0\n0.0 8.0"s },
      { 3, "6.0 0.0 0.0\n0.0 8.0 0.0\n0.0 0.0 10.0"s }
    };
    return "$lattice"s + extra + '\n' + LATTICES.at(periodic) + '\n';
  };

  constexpr double EPS = 1.0e-14;

  for (unsigned periodic = 1u; periodic <= 3u; periodic++) {
    const auto periodic_kw = "$periodic "s + std::to_string(periodic) + '\n';

    {
      TurbomoleFormat tmol;
      Molecule molecule;
      // $periodic is specified but $cell/$lattice is missed
      EXPECT_FALSE(tmol.readString(periodic_kw + "$end"s, molecule));
    }

    for (unsigned n = 1u; n <= 3u; n++) {
      for (const auto& len : {
             ""s,      // bohr
             " angs"s, // ångström
             "angs"s   // INVALID: space required
           }) {
        for (const auto& str : {
               periodic_kw + cell(n, len) + "$end"s,
               periodic_kw + lattice(n, len) + "$end"s,
               cell(n, len) + periodic_kw + "$end"s,
               lattice(n, len) + periodic_kw + "$end"s,
             }) {
          TurbomoleFormat tmol;
          Molecule molecule;

          if (periodic != n || len == "angs"s) {
            // $periodic and $cell/$lattice mismatch, e.g.
            //
            // $periodic 3
            // $cell 6.0  # 1D
            // $end
            //
            // $periodic 3
            // $lattice
            // 6.0 0.0  # 2D
            // 0.0 8.0  # 2D
            // $end
            //
            // OR '$cellangs' or '$latticeangs'
            EXPECT_FALSE(tmol.readString(str, molecule)) << str;
          } else {
            // $periodic and $cell/$lattice match
            ASSERT_TRUE(tmol.readString(str, molecule)) << str << '\n'
                                                        << tmol.error();
            const auto* const uc = molecule.unitCell();
            ASSERT_NE(uc, nullptr);
            const double factor = len.empty() ? ANGSTROM_TO_BOHR : 1.0;
            const auto& a = uc->aVector();
            const auto& b = uc->bVector();
            const auto& c = uc->cVector();

            if (periodic == 1) {
              EXPECT_EQ(a * factor, Vector3(6.0, 0.0, 0.0));
              EXPECT_NEAR(b[0], 0.0, EPS);
              EXPECT_EQ(b[1], 100.0);
              EXPECT_NEAR(b[2], 0.0, EPS);
              EXPECT_NEAR(c[0], 0.0, EPS);
              EXPECT_NEAR(c[1], 0.0, EPS);
              EXPECT_EQ(c[2], 100.0);
            } else if (periodic == 2) {
              EXPECT_EQ(a * factor, Vector3(6.0, 0.0, 0.0));
              EXPECT_NEAR(b[0], 0.0, EPS);
              EXPECT_EQ(b[1] * factor, 8.0);
              EXPECT_NEAR(b[2], 0.0, EPS);
              EXPECT_NEAR(c[0], 0.0, EPS);
              EXPECT_NEAR(c[1], 0.0, EPS);
              EXPECT_EQ(c[2], 100.0);
            } else {
              EXPECT_EQ(a * factor, Vector3(6.0, 0.0, 0.0));
              EXPECT_NEAR(b[0], 0.0, EPS);
              EXPECT_EQ(b[1] * factor, 8.0);
              EXPECT_NEAR(b[2], 0.0, EPS);
              EXPECT_NEAR(c[0], 0.0, EPS);
              EXPECT_NEAR(c[1], 0.0, EPS);
              EXPECT_NEAR(c[2] * factor, 10.0, EPS);
            }
          }
        }
      }
    }
  }
}

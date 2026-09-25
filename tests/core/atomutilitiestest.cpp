/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/atomutilities.h>
#include <avogadro/core/elements.h>

using Avogadro::Core::AtomUtilities;
using Avogadro::Core::Elements;

namespace {
// The table is quoted to three decimals, so match to within half of the last
// digit rather than exactly.
const double tol = 0.0005;
} // namespace

TEST(AtomUtilitiesTest, idealBondLengthCommonOrganic)
{
  // The bonds users draw constantly should reproduce textbook geometry, not
  // the sum of covalent radii (which gives 1.500 and 1.070 for the first two).
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 6, 1), 1.540, tol); // C-C
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 1, 1), 1.090, tol); // C-H
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 7, 1), 1.469, tol); // C-N
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 8, 1), 1.426, tol); // C-O
  EXPECT_NEAR(AtomUtilities::idealBondLength(7, 1, 1), 1.012, tol); // N-H
  EXPECT_NEAR(AtomUtilities::idealBondLength(8, 1, 1), 0.958, tol); // O-H

  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 6, 2), 1.331, tol); // C=C
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 8, 2), 1.220, tol); // C=O
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 7, 2), 1.279, tol); // C=N

  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 6, 3), 1.200, tol); // C#C
  EXPECT_NEAR(AtomUtilities::idealBondLength(6, 7, 3), 1.140, tol); // C#N
}

TEST(AtomUtilitiesTest, idealBondLengthPolarAndLonePairBonds)
{
  // The cases the covalent radii sum gets worst: strongly polar bonds are much
  // shorter than the sum, lone-pair rich bonds much longer.
  EXPECT_NEAR(AtomUtilities::idealBondLength(14, 9, 1), 1.570, tol); // Si-F
  EXPECT_NEAR(AtomUtilities::idealBondLength(5, 9, 1), 1.307, tol);  // B-F
  EXPECT_NEAR(AtomUtilities::idealBondLength(15, 9, 1), 1.570, tol); // P-F
  EXPECT_NEAR(AtomUtilities::idealBondLength(8, 14, 1), 1.630, tol); // O-Si

  EXPECT_NEAR(AtomUtilities::idealBondLength(8, 8, 1), 1.475, tol); // O-O
  EXPECT_NEAR(AtomUtilities::idealBondLength(9, 9, 1), 1.412, tol); // F-F
  EXPECT_NEAR(AtomUtilities::idealBondLength(1, 1, 1), 0.741, tol); // H-H
  EXPECT_NEAR(AtomUtilities::idealBondLength(7, 8, 1), 1.440, tol); // N-O
}

TEST(AtomUtilitiesTest, idealBondLengthFallsBackToCovalentRadii)
{
  // An untabulated single bond is exactly the sum of the covalent radii.
  for (auto pair : { std::make_pair(6, 5), std::make_pair(16, 17),
                     std::make_pair(26, 8), std::make_pair(92, 17) }) {
    EXPECT_NEAR(AtomUtilities::idealBondLength(pair.first, pair.second, 1),
                Elements::radiusCovalent(pair.first) +
                  Elements::radiusCovalent(pair.second),
                1e-9);
  }
}

TEST(AtomUtilitiesTest, idealBondLengthMultipleBondsContract)
{
  // Multiple bonds are shorter than single bonds, for tabulated pairs and for
  // pairs that fall through to the covalent radii.
  for (auto pair : { std::make_pair(6, 6), std::make_pair(7, 7),
                     std::make_pair(16, 16), std::make_pair(26, 8) }) {
    const double single =
      AtomUtilities::idealBondLength(pair.first, pair.second, 1);
    const double dbl =
      AtomUtilities::idealBondLength(pair.first, pair.second, 2);
    const double triple =
      AtomUtilities::idealBondLength(pair.first, pair.second, 3);
    EXPECT_LT(dbl, single);
    EXPECT_LT(triple, dbl);
  }

  // Contraction is weaker for heavier elements, so a single scale factor
  // cannot fit both rows: Si=Si must not shrink as much as C=C.
  const double cRatio = AtomUtilities::idealBondLength(6, 6, 2) /
                        AtomUtilities::idealBondLength(6, 6, 1);
  const double siRatio = AtomUtilities::idealBondLength(14, 14, 2) /
                         AtomUtilities::idealBondLength(14, 14, 1);
  EXPECT_GT(siRatio, cRatio);
}

TEST(AtomUtilitiesTest, idealBondLengthArgumentOrderAndBadOrders)
{
  // Swapping the two atoms must give a bit-identical answer.
  for (unsigned char z1 = 1; z1 < 40; ++z1) {
    for (unsigned char z2 = 1; z2 < 40; ++z2) {
      for (unsigned char order = 1; order <= 3; ++order) {
        EXPECT_DOUBLE_EQ(AtomUtilities::idealBondLength(z1, z2, order),
                         AtomUtilities::idealBondLength(z2, z1, order));
      }
    }
  }

  // Orders outside 1-3 (aromatic, dative, unset) fall back to a single bond.
  const double single = AtomUtilities::idealBondLength(6, 6, 1);
  EXPECT_DOUBLE_EQ(AtomUtilities::idealBondLength(6, 6, 0), single);
  EXPECT_DOUBLE_EQ(AtomUtilities::idealBondLength(6, 6, 4), single);
  EXPECT_DOUBLE_EQ(AtomUtilities::idealBondLength(6, 6, 255), single);
}

TEST(AtomUtilitiesTest, idealBondLengthHandlesEveryElement)
{
  // Nothing in range may return a non-positive or absurd length, and the
  // lookup must stay in bounds for custom/invalid atomic numbers.
  for (unsigned int z1 = 1; z1 < 119; ++z1) {
    for (unsigned int z2 = 1; z2 < 119; ++z2) {
      const double length = AtomUtilities::idealBondLength(
        static_cast<unsigned char>(z1), static_cast<unsigned char>(z2), 1);
      EXPECT_GT(length, 0.0);
      EXPECT_LT(length, 6.0);
    }
  }
  EXPECT_GT(AtomUtilities::idealBondLength(255, 6, 1), 0.0);
}

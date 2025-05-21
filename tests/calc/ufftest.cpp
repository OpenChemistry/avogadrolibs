/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "calctests.h"

#include <gtest/gtest.h>

#include <avogadro/calc/gradients.h>
#include <avogadro/calc/uff.h>

#include <avogadro/core/angletools.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <cmath>
#include <vector>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::XyzFormat;

// methane.xyz uses atomic symbols to identify atoms
TEST(UffTest, readAndEnergy)
{
  XyzFormat xyz;
  Molecule molecule;
  EXPECT_TRUE(xyz.readFile(AVOGADRO_DATA "/data/xyz/methane.xyz", molecule));
  ASSERT_EQ(xyz.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), 5);
}

/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

#include <avogadro/io/mmtfformat.h>

using Avogadro::DEG_TO_RAD;
using Avogadro::MatrixX;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;
using Avogadro::Core::Residue;
using Avogadro::Core::Variant;
using Avogadro::Io::MMTFFormat;

TEST(MMTFTest, readFile)
{
  MMTFFormat mmtf;
  Molecule molecule;
  mmtf.readFile(std::string(AVOGADRO_DATA) + "/data/4HHB.mmtf", molecule);

  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(),
            "THE CRYSTAL STRUCTURE OF HUMAN DEOXYHAEMOGLOBIN AT 1.74 ANGSTROMS "
            "RESOLUTION");
}

TEST(MMTFTEST, unitCell)
{
  MMTFFormat mmtf;
  Molecule molecule;
  mmtf.readFile(std::string(AVOGADRO_DATA) + "/data/4HHB.mmtf", molecule);

  auto cell = molecule.unitCell();

  EXPECT_NEAR(cell->a(), 63.150, 1e-3);
  EXPECT_NEAR(cell->b(), 83.590, 1e-3);
  EXPECT_NEAR(cell->c(), 53.800, 1e-3);
  EXPECT_NEAR(cell->alpha(), 90.00 * DEG_TO_RAD, 1e-3);
  EXPECT_NEAR(cell->beta(), 99.34 * DEG_TO_RAD, 1e-3);
  EXPECT_NEAR(cell->gamma(), 90.00 * DEG_TO_RAD, 1e-3);
}

TEST(MMTFTest, atoms)
{
  MMTFFormat mmtf;
  Molecule molecule;
  mmtf.readFile(std::string(AVOGADRO_DATA) + "/data/4HHB.mmtf", molecule);

  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(4779));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(7));
  EXPECT_NEAR(atom.position3d().x(), 6.204, 1e-3);
  EXPECT_NEAR(atom.position3d().y(), 16.869, 1e-3);
  EXPECT_NEAR(atom.position3d().z(), 4.854, 1e-3);

  // Random alpha carbon
  atom = molecule.atom(296);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_NEAR(atom.position3d().x(), 10.167, 1e-3);
  EXPECT_NEAR(atom.position3d().y(), -7.889, 1e-3);
  EXPECT_NEAR(atom.position3d().z(), -16.138, 1e-3);

  // Final water
  atom = molecule.atom(4778);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(8));
  EXPECT_NEAR(atom.position3d().x(), -1.263, 1e-3);
  EXPECT_NEAR(atom.position3d().y(), -2.837, 1e-3);
  EXPECT_NEAR(atom.position3d().z(), -21.251, 1e-3);
}

TEST(MMTFTest, bonds)
{
  MMTFFormat mmtf;
  Molecule molecule;
  mmtf.readFile(std::string(AVOGADRO_DATA) + "/data/4HHB.mmtf", molecule);

  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(4700));

  // First nitrogen to alpha carbon
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));

  bond = molecule.bond(6);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(7));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(8));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(MMTFTest, residues)
{
  MMTFFormat mmtf;
  Molecule molecule;
  mmtf.readFile(std::string(AVOGADRO_DATA) + "/data/4HHB.mmtf", molecule);

  Residue& res = molecule.residue(0);
  EXPECT_EQ(res.residueId(), static_cast<size_t>(1));
  EXPECT_EQ(res.residueName(), "VAL");
  EXPECT_EQ(res.residueAtoms().size(), static_cast<size_t>(7));

  // The last Heme
  Residue& res2 = molecule.residue(579);
  EXPECT_EQ(res2.residueId(), static_cast<size_t>(148));
  EXPECT_EQ(res2.residueName(), "HEM");
  EXPECT_EQ(res2.residueAtoms().size(), static_cast<size_t>(43));

  // The first water
  Residue& res3 = molecule.residue(580);
  EXPECT_EQ(res3.residueId(), static_cast<size_t>(143));
  EXPECT_EQ(res3.residueName(), "HOH");
  EXPECT_EQ(res3.residueAtoms().size(), static_cast<size_t>(1));
}

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/io/cjsonformat.h>

using Avogadro::MatrixX;
using Avogadro::PI_F;
using Avogadro::Real;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Core::Variant;
using Avogadro::Io::CjsonFormat;
using namespace std::string_literals;

TEST(CjsonTest, readFile)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").type(), Variant::String);
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");

  EXPECT_EQ(molecule.data("inchi").type(), Variant::String);
  EXPECT_EQ(molecule.data("inchi").toString(), "1/C2H6/c1-2/h1-2H3");
}

TEST(CjsonTest, atomicNumberEdgeCase)
{
  for (const auto* s : {
         R"({"chemicalJson": 0, "name": "negative Z",
  "atoms": {"coords": {"3d": [1.0, 2.0, 3.0]}, "elements": {"number": [-1]}}})",

         R"({"chemicalJson": 1, "name": "ununennium",
  "atoms": {"coords": {"3d": [1.0, 2.0, 3.0]}, "elements": {"number": [119]}},
  "properties": {"totalCharge": 1, "totalSpinMultiplicity": 1}})",
       }) {
    CjsonFormat cjson;
    Molecule molecule;
    EXPECT_FALSE(cjson.readString(s, molecule)) << s;
    EXPECT_EQ(cjson.error(), "Error: atomic number is invalid.\n");
  }

  for (const auto* s : {
         R"({"chemicalJson": 0, "name": "ghost",
  "atoms": {"coords": {"3d": [1.0, 2.0, 3.0]}, "elements": {"number": [0]}}})",

         R"({"chemicalJson": 1, "name": "oganesson",
  "atoms": {"coords": {"3d": [1.0, 2.0, 3.0]}, "elements": {"number": [118]}},
  "properties": {"totalCharge": 0, "totalSpinMultiplicity": 1}})",
       }) {
    CjsonFormat cjson;
    Molecule molecule;
    EXPECT_TRUE(cjson.readString(s, molecule)) << s;
  }
}

TEST(CjsonTest, readInvalidPeriodicFile)
{
  const auto error_cell_params =
    "cell parameters do not give linear-independent lattice vectors\n"s;
  const auto error_cellVectors = "cellVectors are not linear independent\n"s;
  for (const auto& [file, err] : {
         std::make_pair("impossible.cjson"s, error_cell_params),
         std::make_pair("lin-dep-cellVectors.cjson"s, error_cellVectors),
         std::make_pair("lin-dep2.cjson"s, error_cell_params),
         std::make_pair("zero-a-cellVectors.cjson"s, error_cellVectors),
         std::make_pair("zero-a.cjson"s, error_cell_params),
         std::make_pair("zero-alpha.cjson"s, error_cell_params),
         std::make_pair("zero-b-cellVectors.cjson"s, error_cellVectors),
         std::make_pair("zero-b.cjson"s, error_cell_params),
         std::make_pair("zero-beta.cjson"s, error_cell_params),
         std::make_pair("zero-c-cellVectors.cjson"s, error_cellVectors),
         std::make_pair("zero-c.cjson"s, error_cell_params),
         std::make_pair("zero-gamma.cjson"s, error_cell_params),
       }) {
    CjsonFormat cjson;
    Molecule molecule;
    auto f = std::string(AVOGADRO_DATA) + "/data/cjson/singular/" + file;
    EXPECT_FALSE(cjson.readFile(f, molecule)) << f;
    EXPECT_EQ(cjson.error(), err) << f;
  }
}

TEST(CjsonTest, atoms)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  Atom atom = molecule.atom(0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  atom = molecule.atom(1);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));
  EXPECT_EQ(atom.position3d().x(), 0.751621);
  EXPECT_EQ(atom.position3d().y(), -0.022441);
  EXPECT_EQ(atom.position3d().z(), -0.020839);

  atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
}

TEST(CjsonTest, bonds)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));

  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
  bond = molecule.bond(6);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(4));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(7));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(CjsonTest, crystal)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/rutile.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "TiO2 rutile");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(6));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(0));

  const UnitCell* unitCell = molecule.unitCell();
  ASSERT_NE(unitCell, (UnitCell*)nullptr);
  EXPECT_TRUE(std::fabs((float)unitCell->a() - 2.95812f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->b() - 4.59373f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->c() - 4.59373f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->alpha() - (.5f * PI_F)) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->beta() - (.5f * PI_F)) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)unitCell->gamma() - (.5f * PI_F)) < 1e-5f);

  Atom atom = molecule.atom(5);
  EXPECT_EQ(atom.atomicNumber(), 8);
  EXPECT_TRUE(std::fabs((float)atom.position3d().x() - 1.479060f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)atom.position3d().y() - 3.699331f) < 1e-5f);
  EXPECT_TRUE(std::fabs((float)atom.position3d().z() - 0.894399f) < 1e-5f);

  std::string cjsonStr;
  cjson.writeString(cjsonStr, molecule);
  Molecule otherMolecule;
  cjson.readString(cjsonStr, otherMolecule);

  const UnitCell* otherUnitCell = otherMolecule.unitCell();
  ASSERT_NE(otherUnitCell, (UnitCell*)nullptr);
  EXPECT_FLOAT_EQ((float)otherUnitCell->a(), (float)unitCell->a());
  EXPECT_FLOAT_EQ((float)otherUnitCell->b(), (float)unitCell->b());
  EXPECT_FLOAT_EQ((float)otherUnitCell->c(), (float)unitCell->c());
  EXPECT_FLOAT_EQ((float)otherUnitCell->alpha(), (float)unitCell->alpha());
  EXPECT_FLOAT_EQ((float)otherUnitCell->beta(), (float)unitCell->beta());
  EXPECT_FLOAT_EQ((float)otherUnitCell->gamma(), (float)unitCell->gamma());

  Atom otherAtom = otherMolecule.atom(5);
  EXPECT_EQ(otherAtom.atomicNumber(), atom.atomicNumber());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().x(),
                  (float)atom.position3d().x());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().y(),
                  (float)atom.position3d().y());
  EXPECT_FLOAT_EQ((float)otherAtom.position3d().z(),
                  (float)atom.position3d().z());
}

TEST(CjsonTest, saveFile)
{
  CjsonFormat cjson;
  Molecule savedMolecule, molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/ethane.cjson", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  success = cjson.writeFile("ethanetmp.cjson", savedMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  // Now read the file back in and check a few key values are still present.
  success = cjson.readFile("ethanetmp.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.data("name").toString(), "Ethane");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(8));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(7));
  Atom atom = molecule.atom(7);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(1));
  EXPECT_EQ(atom.position3d().x(), -1.184988);
  EXPECT_EQ(atom.position3d().y(), 0.004424);
  EXPECT_EQ(atom.position3d().z(), -0.987522);
  Bond bond = molecule.bond(0);
  EXPECT_EQ(bond.atom1().index(), static_cast<size_t>(0));
  EXPECT_EQ(bond.atom2().index(), static_cast<size_t>(1));
  EXPECT_EQ(bond.order(), static_cast<unsigned char>(1));
}

TEST(CjsonTest, conformers)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/conformers.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(14));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(13));
  EXPECT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(3));

  // okay now save it and make sure we still have the same number
  success = cjson.writeFile("conformertmp.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  Molecule otherMolecule;
  success = cjson.readFile("conformertmp.cjson", otherMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(otherMolecule.atomCount(), static_cast<size_t>(14));
  EXPECT_EQ(otherMolecule.bondCount(), static_cast<size_t>(13));
  EXPECT_EQ(otherMolecule.coordinate3dCount(), static_cast<size_t>(3));
}

TEST(CjsonTest, partialCharges)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readFile(
    std::string(AVOGADRO_DATA) + "/data/cjson/formaldehyde.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(4));
  EXPECT_EQ(molecule.bondCount(), static_cast<size_t>(3));
  EXPECT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(7));

  // check partial charges
  auto types = molecule.partialChargeTypes();
  // should be Loewdin and Mulliken
  EXPECT_EQ(types.size(), static_cast<size_t>(2));
  MatrixX loewdinCharges = molecule.partialCharges("Loewdin");
  // should be 4 atoms
  EXPECT_EQ(loewdinCharges.rows(), static_cast<size_t>(4));
  // check the charges on atoms
  EXPECT_EQ(loewdinCharges(0, 0), 0.133356);
  EXPECT_EQ(loewdinCharges(1, 0), -0.112557);

  MatrixX mullikenCharges = molecule.partialCharges("Mulliken");
  // should be 4 atoms
  EXPECT_EQ(mullikenCharges.rows(), static_cast<size_t>(4));
  // check the charges on atoms
  EXPECT_EQ(mullikenCharges(0, 0), 0.16726);
  EXPECT_EQ(mullikenCharges(1, 0), -0.201292);

  // okay now save it and make sure we still have the same number
  success = cjson.writeFile("formaldehysetmp.cjson", molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");

  Molecule otherMolecule;
  success = cjson.readFile("formaldehysetmp.cjson", otherMolecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
  EXPECT_EQ(otherMolecule.atomCount(), static_cast<size_t>(4));
  EXPECT_EQ(otherMolecule.bondCount(), static_cast<size_t>(3));
  EXPECT_EQ(otherMolecule.coordinate3dCount(), static_cast<size_t>(7));
  // check partial charges
  types = otherMolecule.partialChargeTypes();
  // should be Loewdin and Mulliken
  EXPECT_EQ(types.size(), static_cast<size_t>(2));
  loewdinCharges = otherMolecule.partialCharges("Loewdin");
  // should be 4 atoms
  EXPECT_EQ(loewdinCharges.rows(), static_cast<size_t>(4));
  // check the charges on atoms
  EXPECT_EQ(loewdinCharges(0, 0), 0.133356);
  EXPECT_EQ(loewdinCharges(1, 0), -0.112557);
  mullikenCharges = otherMolecule.partialCharges("Mulliken");
  // should be 4 atoms
  EXPECT_EQ(mullikenCharges.rows(), static_cast<size_t>(4));
  // check the charges on atoms
  EXPECT_EQ(mullikenCharges(0, 0), 0.16726);
  EXPECT_EQ(mullikenCharges(1, 0), -0.201292);
}

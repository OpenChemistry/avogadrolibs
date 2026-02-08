/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "utils.h"

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

using Avogadro::Index;
using Avogadro::Vector2;
using Avogadro::Vector3;
using Avogadro::Vector3f;
using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Color3f;
using Avogadro::Core::Mesh;
using Avogadro::Core::Molecule;
using Avogadro::Core::UnitCell;
using Avogadro::Core::Variant;
using Avogadro::Core::VariantMap;

class MoleculeTest : public testing::Test
{
public:
  MoleculeTest();

protected:
  Molecule m_testMolecule;
};

MoleculeTest::MoleculeTest()
{
  Atom o1 = m_testMolecule.addAtom(8);
  Atom h2 = m_testMolecule.addAtom(1);
  Atom h3 = m_testMolecule.addAtom(1);

  o1.setPosition3d(Vector3(0, 0, 0));
  h2.setPosition3d(Vector3(0.6, -0.5, 0));
  h3.setPosition3d(Vector3(-0.6, -0.5, 0));

  o1.setPosition2d(Vector2(0, 0));
  h2.setPosition2d(Vector2(0.6, -0.5));
  h3.setPosition2d(Vector2(-0.6, -0.5));

  // Add some data
  VariantMap data;
  data.setValue("test", Variant("test"));
  m_testMolecule.setDataMap(data);

  // Add some bonds
  m_testMolecule.perceiveBondsSimple();

  Mesh* mesh = m_testMolecule.addMesh();

  Array<Vector3f> vertices;
  Array<Vector3f> normals;
  Array<Color3f> colors;

  Color3f color = Color3f(23, 23, 23);
  colors.push_back(color);

  Vector3f vec(1.2f, 1.3f, 1.4f);

  vertices.push_back(vec);
  normals.push_back(vec);

  mesh->setColors(colors);
  mesh->setNormals(normals);
  mesh->setVertices(vertices);
  mesh->setIsoValue(1.2f);
  mesh->setName("testmesh");
  mesh->setOtherMesh(1);
  mesh->setStable(false);
}

TEST_F(MoleculeTest, addAtom)
{
  Molecule molecule;
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(0));

  Avogadro::Core::Atom atom = molecule.addAtom(6);
  EXPECT_EQ(atom.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(1));
  EXPECT_EQ(atom.index(), 0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));

  Avogadro::Core::Atom atom2 = molecule.addAtom(1);
  EXPECT_EQ(atom2.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(2));
  EXPECT_EQ(atom2.index(), 1);
  EXPECT_EQ(atom2.atomicNumber(), static_cast<unsigned char>(1));
}

TEST_F(MoleculeTest, removeAtom)
{
  Molecule molecule;
  Atom atom0 = molecule.addAtom(6);
  Atom atom1 = molecule.addAtom(1);
  Atom atom2 = molecule.addAtom(1);
  Atom atom3 = molecule.addAtom(1);
  Atom atom4 = molecule.addAtom(1);
  molecule.addBond(atom0, atom1, 1);
  molecule.addBond(atom0, atom2, 1);
  molecule.addBond(atom0, atom3, 1);
  molecule.addBond(atom0, atom4, 1);

  EXPECT_EQ(5, molecule.atomCount());
  EXPECT_EQ(4, molecule.bondCount());

  molecule.removeAtom(atom0);

  EXPECT_EQ(4, molecule.atomCount());
  EXPECT_EQ(0, molecule.bondCount());

  molecule.clearAtoms();

  EXPECT_EQ(0, molecule.atomCount());
}

TEST_F(MoleculeTest, addBond)
{
  Molecule molecule;
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(0));

  Atom a = molecule.addAtom(1);
  Atom b = molecule.addAtom(1);
  Bond bondAB = molecule.addBond(a, b);
  EXPECT_TRUE(bondAB.isValid());
  EXPECT_EQ(bondAB.molecule(), &molecule);
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(1));
  EXPECT_EQ(bondAB.index(), static_cast<Index>(0));
  EXPECT_EQ(bondAB.atom1().index(), a.index());
  EXPECT_EQ(bondAB.atom2().index(), b.index());
  EXPECT_EQ(bondAB.order(), static_cast<unsigned char>(1));

  Atom c = molecule.addAtom(1);
  Bond bondBC = molecule.addBond(b, c, 2);
  EXPECT_TRUE(bondBC.isValid());
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(2));
  EXPECT_EQ(bondBC.index(), static_cast<Index>(1));
  EXPECT_EQ(bondBC.order(), static_cast<unsigned char>(2));

  // try to lookup nonexistent bond
  Bond bond = molecule.bond(a, c);
  EXPECT_FALSE(bond.isValid());

  // try to lookup bond between a and b
  bond = molecule.bond(a, b);
  EXPECT_TRUE(bond.isValid());
  EXPECT_EQ(bond.molecule(), &molecule);
  EXPECT_EQ(bond.atom1().index(), a.index());
  EXPECT_EQ(bond.atom2().index(), b.index());

  // try to lookup bond between b and c by index
  bond = molecule.bond(1);
  EXPECT_TRUE(bond.isValid());
  EXPECT_EQ(bond.molecule(), &molecule);
  EXPECT_EQ(bond.atom1().index(), b.index());
  EXPECT_EQ(bond.atom2().index(), c.index());
}

TEST_F(MoleculeTest, removeBond)
{
  Molecule molecule;
  Atom a = molecule.addAtom(1);
  Atom b = molecule.addAtom(1);
  Bond bondAB = molecule.addBond(a, b);
  Atom c = molecule.addAtom(1);
  molecule.addBond(b, c, 2);

  EXPECT_EQ(3, molecule.atomCount());
  EXPECT_EQ(2, molecule.bondCount());
  EXPECT_TRUE(molecule.bond(a, b).isValid());
  EXPECT_TRUE(molecule.bond(b, c).isValid());

  molecule.removeBond(bondAB);

  EXPECT_EQ(3, molecule.atomCount());
  EXPECT_EQ(1, molecule.bondCount());
  EXPECT_FALSE(molecule.bond(a, b).isValid());
  EXPECT_TRUE(molecule.bond(b, c).isValid());

  molecule.clearBonds();

  EXPECT_EQ(0, molecule.bondCount());
}

TEST_F(MoleculeTest, findBond)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Bond b = molecule.addBond(a1, a2, 1);

  EXPECT_EQ(molecule.bond(a1, a2).index(), b.index());
  EXPECT_EQ(molecule.bond(a2, a1).index(), b.index());

  Array<Bond> bonds = molecule.bonds(a1);
  EXPECT_EQ(bonds.size(), 1);

  Atom a3 = molecule.addAtom(7);
  molecule.addBond(a1, a3, 1);
  EXPECT_EQ(molecule.bonds(a1).size(), 2);
  EXPECT_EQ(molecule.bonds(a3).size(), 1);
}

TEST_F(MoleculeTest, setData)
{
  Molecule molecule;
  molecule.setData("name", "ethanol");
  EXPECT_EQ(molecule.data("name").toString(), "ethanol");
}

TEST_F(MoleculeTest, dataMap)
{
  Molecule molecule;
  molecule.setData("name", "ethanol");
  molecule.setData("formula", "C2H6O");
  VariantMap varMap = molecule.dataMap();
  varMap.setValue("SMILES", "CCO");
  molecule.setDataMap(varMap);
  molecule.dataMap().setValue("CAS", "64-17-5");

  std::vector<std::string> dataNames = molecule.dataMap().names();
  EXPECT_EQ(dataNames.size(), 4);
  EXPECT_EQ(molecule.hasData("name"), true);
  EXPECT_EQ(molecule.hasData("invalid"), false);
  EXPECT_EQ(molecule.data("name").toString(), "ethanol");
  EXPECT_EQ(molecule.data("formula").toString(), "C2H6O");
  EXPECT_EQ(molecule.data("SMILES").toString(), "CCO");
  EXPECT_EQ(molecule.data("CAS").toString(), "64-17-5");
}

TEST_F(MoleculeTest, perceiveBondsSimple)
{
  Molecule molecule;
  Atom o1 = molecule.addAtom(8);
  Atom h2 = molecule.addAtom(1);
  Atom h3 = molecule.addAtom(1);

  o1.setPosition3d(Vector3(0, 0, 0));
  h2.setPosition3d(Vector3(0.6, -0.5, 0));
  h3.setPosition3d(Vector3(-0.6, -0.5, 0));
  EXPECT_EQ(molecule.bondCount(), 0);

  molecule.perceiveBondsSimple();
  EXPECT_EQ(molecule.bondCount(), 2);
  EXPECT_TRUE(molecule.bond(o1, h2).isValid());
  EXPECT_TRUE(molecule.bond(o1, h3).isValid());
  EXPECT_FALSE(molecule.bond(h2, h3).isValid());
}

TEST_F(MoleculeTest, copy)
{
  Molecule copy(m_testMolecule);

  assertEqual(m_testMolecule, copy);
}

TEST_F(MoleculeTest, assignment)
{
  Molecule assign;
  assign = m_testMolecule;

  assertEqual(m_testMolecule, assign);
}

TEST_F(MoleculeTest, estimateVelocities)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(1);
  Atom a2 = molecule.addAtom(1);

  Array<Vector3> coords0;
  coords0.push_back(Vector3(0.0, 0.0, 0.0));
  coords0.push_back(Vector3(1.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords0, 0);
  molecule.setTimeStep(0.0, 0);

  Array<Vector3> coords1;
  coords1.push_back(Vector3(1.0, 0.0, 0.0));
  coords1.push_back(Vector3(2.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords1, 1);
  molecule.setTimeStep(1.0, 1);

  Array<Vector3> coords2;
  coords2.push_back(Vector3(2.0, 0.0, 0.0));
  coords2.push_back(Vector3(3.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords2, 2);
  molecule.setTimeStep(2.0, 2);

  molecule.estimateVelocities();

  Array<Vector3> v0 = molecule.velocities(0);
  ASSERT_EQ(v0.size(), 2);
  EXPECT_NEAR(v0[0].x(), 1.0, 1e-5);
  EXPECT_NEAR(v0[1].x(), 1.0, 1e-5);

  Array<Vector3> v1 = molecule.velocities(1);
  ASSERT_EQ(v1.size(), 2);
  EXPECT_NEAR(v1[0].x(), 1.0, 1e-5);
  EXPECT_NEAR(v1[1].x(), 1.0, 1e-5);

  Array<Vector3> v2 = molecule.velocities(2);
  ASSERT_EQ(v2.size(), 2);
  EXPECT_NEAR(v2[0].x(), 1.0, 1e-5);
  EXPECT_NEAR(v2[1].x(), 1.0, 1e-5);
}

TEST_F(MoleculeTest, formulaCompositionBasic)
{
  // Test basic composition without unit cell (H2O from test fixture)
  std::map<std::string, size_t> comp = m_testMolecule.formulaComposition();
  EXPECT_EQ(comp["O"], 1);
  EXPECT_EQ(comp["H"], 2);
  EXPECT_EQ(comp.size(), 2);
}

TEST_F(MoleculeTest, formulaCompositionIsotopes)
{
  Molecule molecule;

  // Add regular hydrogen
  Atom h1 = molecule.addAtom(1);
  h1.setPosition3d(Vector3(0, 0, 0));

  // Add deuterium (hydrogen isotope 2)
  Atom d1 = molecule.addAtom(1);
  d1.setPosition3d(Vector3(1, 0, 0));
  molecule.setIsotope(d1.index(), 2);

  // Add tritium (hydrogen isotope 3)
  Atom t1 = molecule.addAtom(1);
  t1.setPosition3d(Vector3(2, 0, 0));
  molecule.setIsotope(t1.index(), 3);

  // Add carbon-13
  Atom c13 = molecule.addAtom(6);
  c13.setPosition3d(Vector3(3, 0, 0));
  molecule.setIsotope(c13.index(), 13);

  // Add regular carbon
  Atom c12 = molecule.addAtom(6);
  c12.setPosition3d(Vector3(4, 0, 0));

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  EXPECT_EQ(comp["H"], 1);
  EXPECT_EQ(comp["D"], 1);
  EXPECT_EQ(comp["T"], 1);
  EXPECT_EQ(comp["13C"], 1);
  EXPECT_EQ(comp["C"], 1);
}

TEST_F(MoleculeTest, formulaCompositionUnitCellCorner)
{
  Molecule molecule;

  // Create a simple cubic unit cell (10 Angstrom sides)
  UnitCell* cell = new UnitCell(10.0, 10.0, 10.0, M_PI / 2, M_PI / 2, M_PI / 2);
  molecule.setUnitCell(cell);

  // Add 8 corner atoms (each at a corner of the unit cell)
  // Each corner atom should count as 1/8, so 8 corners = 1 atom
  Vector3 corners[8] = { Vector3(0, 0, 0),   Vector3(10, 0, 0),
                         Vector3(0, 10, 0),  Vector3(0, 0, 10),
                         Vector3(10, 10, 0), Vector3(10, 0, 10),
                         Vector3(0, 10, 10), Vector3(10, 10, 10) };

  for (int i = 0; i < 8; ++i) {
    Atom a = molecule.addAtom(11); // Sodium
    a.setPosition3d(corners[i]);
  }

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  // 8 corners * 1/8 = 1
  EXPECT_EQ(comp["Na"], 1);
}

TEST_F(MoleculeTest, formulaCompositionUnitCellEdge)
{
  Molecule molecule;

  // Create a simple cubic unit cell (10 Angstrom sides)
  UnitCell* cell = new UnitCell(10.0, 10.0, 10.0, M_PI / 2, M_PI / 2, M_PI / 2);
  molecule.setUnitCell(cell);

  // Add 4 edge atoms (each on an edge of the unit cell, 2 coords at 0 or 1)
  // Each edge atom should count as 1/4, so 4 edges = 1 atom
  Vector3 edges[4] = {
    Vector3(5, 0, 0),  // edge along x at y=0, z=0
    Vector3(5, 10, 0), // edge along x at y=1, z=0
    Vector3(5, 0, 10), // edge along x at y=0, z=1
    Vector3(5, 10, 10) // edge along x at y=1, z=1
  };

  for (int i = 0; i < 4; ++i) {
    Atom a = molecule.addAtom(17); // Chlorine
    a.setPosition3d(edges[i]);
  }

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  // 4 edges * 1/4 = 1
  EXPECT_EQ(comp["Cl"], 1);
}

TEST_F(MoleculeTest, formulaCompositionUnitCellFace)
{
  Molecule molecule;

  // Create a simple cubic unit cell (10 Angstrom sides)
  UnitCell* cell = new UnitCell(10.0, 10.0, 10.0, M_PI / 2, M_PI / 2, M_PI / 2);
  molecule.setUnitCell(cell);

  // Add 2 face atoms (each on a face of the unit cell, 1 coord at 0 or 1)
  // Each face atom should count as 1/2, so 2 faces = 1 atom
  Vector3 faces[2] = {
    Vector3(5, 5, 0), // face at z=0
    Vector3(5, 5, 10) // face at z=1
  };

  for (int i = 0; i < 2; ++i) {
    Atom a = molecule.addAtom(35); // Bromine
    a.setPosition3d(faces[i]);
  }

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  // 2 faces * 1/2 = 1
  EXPECT_EQ(comp["Br"], 1);
}

TEST_F(MoleculeTest, formulaCompositionUnitCellInterior)
{
  Molecule molecule;

  // Create a simple cubic unit cell (10 Angstrom sides)
  UnitCell* cell = new UnitCell(10.0, 10.0, 10.0, M_PI / 2, M_PI / 2, M_PI / 2);
  molecule.setUnitCell(cell);

  // Add an interior atom (no coords at 0 or 1)
  // Should count as 1
  Atom a = molecule.addAtom(26); // Iron
  a.setPosition3d(Vector3(5, 5, 5));

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  EXPECT_EQ(comp["Fe"], 1);
}

TEST_F(MoleculeTest, formulaCompositionUnitCellMixed)
{
  Molecule molecule;

  // Create a simple cubic unit cell (10 Angstrom sides)
  UnitCell* cell = new UnitCell(10.0, 10.0, 10.0, M_PI / 2, M_PI / 2, M_PI / 2);
  molecule.setUnitCell(cell);

  // NaCl rock salt structure simulation:
  // 8 Na at corners = 8 * 1/8 = 1 Na
  Vector3 corners[8] = { Vector3(0, 0, 0),   Vector3(10, 0, 0),
                         Vector3(0, 10, 0),  Vector3(0, 0, 10),
                         Vector3(10, 10, 0), Vector3(10, 0, 10),
                         Vector3(0, 10, 10), Vector3(10, 10, 10) };
  for (int i = 0; i < 8; ++i) {
    Atom a = molecule.addAtom(11); // Na
    a.setPosition3d(corners[i]);
  }

  // 6 Cl at face centers = 6 * 1/2 = 3 Cl... but we want 1 Cl
  // So add 2 face atoms for 1 Cl
  Atom cl1 = molecule.addAtom(17);
  cl1.setPosition3d(Vector3(5, 5, 0)); // z=0 face
  Atom cl2 = molecule.addAtom(17);
  cl2.setPosition3d(Vector3(5, 5, 10)); // z=1 face

  std::map<std::string, size_t> comp = molecule.formulaComposition();
  EXPECT_EQ(comp["Na"], 1);
  EXPECT_EQ(comp["Cl"], 1);
}

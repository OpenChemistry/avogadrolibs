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
#include <avogadro/core/propertymap.h>
#include <avogadro/core/residue.h>
#include <avogadro/core/unitcell.h>
#include <avogadro/core/vector.h>

using Avogadro::Index;
using Avogadro::MatrixX;
using Avogadro::Vector2;
using Avogadro::Vector3;
using Avogadro::Vector3f;
using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Color3f;
using Avogadro::Core::Mesh;
using Avogadro::Core::Molecule;
using Avogadro::Core::PropertyMap;
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

TEST_F(MoleculeTest, clearAtomsResetsAtomKeyedState)
{
  Molecule molecule;
  Atom a0 = molecule.addAtom(6);
  Atom a1 = molecule.addAtom(1);
  Atom a2 = molecule.addAtom(1);
  molecule.addBond(a0, a1, 1);
  molecule.addBond(a0, a2, 1);

  // residues hold atom indices and must not survive clearAtoms()
  std::string resName("MOL");
  Avogadro::Index resNumber = 1;
  char chain = 'A';
  molecule.addResidue(resName, resNumber, chain);
  molecule.residueProperties().setString("kind", 0, "ligand");

  // conformer-keyed and per-atom-trajectory state
  Array<Vector3> coords(3, Vector3(0.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords, 0);
  molecule.setCoordinate3d(coords, 1);
  molecule.conformerProperties().setDouble("energy", 0, -1.0);
  molecule.setVelocities(coords, 0);
  molecule.setTimeStep(0.5, 0);

  // selection is atom-indexed
  molecule.setAtomSelected(0, true);

  molecule.clearAtoms();

  EXPECT_EQ(0, molecule.atomCount());
  EXPECT_EQ(0, molecule.bondCount());
  EXPECT_EQ(static_cast<Avogadro::Index>(0), molecule.residueCount());
  EXPECT_TRUE(molecule.residueProperties().empty());
  EXPECT_EQ(static_cast<size_t>(0), molecule.coordinate3dCount());
  EXPECT_TRUE(molecule.conformerProperties().empty());
  EXPECT_TRUE(molecule.isSelectionEmpty());
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

// Helper for property-map copy/move tests: populates one of each column type
// (double, int, string, matrix) on atomProperties so a single fixture exercises
// the full PropertyMap surface.
static void populateAtomProperties(Molecule& m)
{
  m.addAtom(6);
  m.addAtom(1);
  m.atomProperties().setDouble("charge", 0, -0.5);
  m.atomProperties().setInt("type", 1, 7);
  m.atomProperties().setString("label", 0, "alpha");
  MatrixX tensor(2, 2);
  tensor << 1.0, 2.0, 3.0, 4.0;
  m.atomProperties().setMatrix("tensor", 0, tensor);
}

TEST_F(MoleculeTest, propertyMapCopyConstruct)
{
  Molecule original;
  populateAtomProperties(original);

  Molecule copy(original);

  EXPECT_DOUBLE_EQ(*copy.atomProperties().getDouble("charge", 0), -0.5);
  EXPECT_EQ(*copy.atomProperties().getInt("type", 1), 7);
  EXPECT_EQ(*copy.atomProperties().getString("label", 0), "alpha");
  ASSERT_TRUE(copy.atomProperties().getMatrix("tensor", 0).has_value());
  MatrixX expected(2, 2);
  expected << 1.0, 2.0, 3.0, 4.0;
  EXPECT_TRUE(copy.atomProperties().getMatrix("tensor", 0)->isApprox(expected));

  // Deep copy: mutating the copy must not bleed back into the original.
  copy.atomProperties().setDouble("charge", 0, 99.0);
  EXPECT_DOUBLE_EQ(*original.atomProperties().getDouble("charge", 0), -0.5);
}

TEST_F(MoleculeTest, propertyMapCopyAssign)
{
  Molecule original;
  populateAtomProperties(original);

  // Pre-populate destination with different data to verify it gets overwritten.
  Molecule assigned;
  assigned.addAtom(8);
  assigned.atomProperties().setDouble("charge", 0, 99.0);
  assigned.atomProperties().setString("stale", 0, "should be replaced");

  assigned = original;

  EXPECT_DOUBLE_EQ(*assigned.atomProperties().getDouble("charge", 0), -0.5);
  EXPECT_EQ(*assigned.atomProperties().getInt("type", 1), 7);
  EXPECT_EQ(*assigned.atomProperties().getString("label", 0), "alpha");
  ASSERT_TRUE(assigned.atomProperties().getMatrix("tensor", 0).has_value());
  // Pre-existing column that did not exist in source must be gone.
  EXPECT_FALSE(assigned.atomProperties().hasStrings("stale"));

  // Deep copy.
  assigned.atomProperties().setDouble("charge", 0, 42.0);
  EXPECT_DOUBLE_EQ(*original.atomProperties().getDouble("charge", 0), -0.5);
}

TEST_F(MoleculeTest, propertyMapMoveConstruct)
{
  Molecule original;
  populateAtomProperties(original);

  Molecule moved(std::move(original));

  EXPECT_DOUBLE_EQ(*moved.atomProperties().getDouble("charge", 0), -0.5);
  EXPECT_EQ(*moved.atomProperties().getInt("type", 1), 7);
  EXPECT_EQ(*moved.atomProperties().getString("label", 0), "alpha");
  ASSERT_TRUE(moved.atomProperties().getMatrix("tensor", 0).has_value());
  MatrixX expected(2, 2);
  expected << 1.0, 2.0, 3.0, 4.0;
  EXPECT_TRUE(
    moved.atomProperties().getMatrix("tensor", 0)->isApprox(expected));
}

TEST_F(MoleculeTest, propertyMapMoveAssign)
{
  Molecule original;
  populateAtomProperties(original);

  Molecule target;
  target.addAtom(8);
  target.atomProperties().setDouble("charge", 0, 99.0);

  target = std::move(original);

  EXPECT_DOUBLE_EQ(*target.atomProperties().getDouble("charge", 0), -0.5);
  EXPECT_EQ(*target.atomProperties().getInt("type", 1), 7);
  ASSERT_TRUE(target.atomProperties().getMatrix("tensor", 0).has_value());
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

TEST_F(MoleculeTest, isotopesFollowTheirAtoms)
{
  // The isotope array is allocated lazily, by the first setIsotope() call, so
  // it is the one per-atom array that is easy to leave out of the bookkeeping
  // every other one gets.
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.setIsotope(2, 13);
  molecule.setIsotope(3, 14);

  // removeAtom() swaps the last atom into the hole, so atom 3's isotope has
  // to travel with it.
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_EQ(molecule.isotope(0), 0);
  EXPECT_EQ(molecule.isotope(1), 14);
  EXPECT_EQ(molecule.isotope(2), 13);

  // And clearing must not leave the old isotopes behind for whatever atoms
  // are added next.
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_EQ(molecule.isotope(0), 0);
}

TEST_F(MoleculeTest, atomLabelsFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.setAtomLabel(0, "zero");
  molecule.setAtomLabel(1, "one");
  molecule.setAtomLabel(2, "two");
  molecule.setAtomLabel(3, "three");

  // removeAtom() swaps the last atom into the hole, so atom 3's label has
  // to travel with it.
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_EQ(molecule.atomLabel(0), "zero");
  EXPECT_EQ(molecule.atomLabel(1), "three");
  EXPECT_EQ(molecule.atomLabel(2), "two");

  molecule.swapAtom(0, 2);
  EXPECT_EQ(molecule.atomLabel(0), "two");
  EXPECT_EQ(molecule.atomLabel(2), "zero");

  // And clearing must not leave the old labels behind for whatever atoms
  // are added next.
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_EQ(molecule.atomLabel(0), "");
}

TEST_F(MoleculeTest, forceVectorsFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.setForceVector(0, Vector3(1, 0, 0));
  molecule.setForceVector(1, Vector3(2, 0, 0));
  molecule.setForceVector(2, Vector3(3, 0, 0));
  molecule.setForceVector(3, Vector3(4, 0, 0));

  // A swap relabels the same structure, so the forces still describe it.
  molecule.swapAtom(0, 2);
  EXPECT_EQ(molecule.forceVector(0), Vector3(3, 0, 0));
  EXPECT_EQ(molecule.forceVector(2), Vector3(1, 0, 0));

  // Removing an atom does not: these forces were computed for a geometry
  // that no longer exists, so they are dropped rather than reindexed.
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_TRUE(molecule.forceVectors().empty());

  // Vector3() is an uninitialized Eigen fixed-size vector, not a zero
  // vector, so forceVector() past the end of a shorter-than-atomCount array
  // is not comparable to a specific value; what matters is that the array
  // itself was actually cleared rather than left with the old atoms' data.
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_TRUE(molecule.forceVectors().empty());
}

TEST_F(MoleculeTest, selectedAtomsFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.setAtomSelected(0, false);
  molecule.setAtomSelected(1, false);
  molecule.setAtomSelected(2, false);
  molecule.setAtomSelected(3, true);

  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_FALSE(molecule.atomSelected(0));
  EXPECT_TRUE(molecule.atomSelected(1)); // former atom 3
  EXPECT_FALSE(molecule.atomSelected(2));

  // swapAtom() was the one place this was missing: the selection is a
  // std::vector<bool>, and std::swap() on its proxy references is unsafe.
  molecule.swapAtom(0, 1);
  EXPECT_TRUE(molecule.atomSelected(0));
  EXPECT_FALSE(molecule.atomSelected(1));

  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_FALSE(molecule.atomSelected(0));
}

TEST_F(MoleculeTest, frozenAtomMaskFollowsAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  // give each atom a distinct per-axis pattern so a misassignment of the
  // 3-entries-per-atom mask cannot pass by coincidence
  molecule.setFrozenAtomAxis(0, 0, true); // atom0: x only
  molecule.setFrozenAtomAxis(1, 1, true); // atom1: y only
  molecule.setFrozenAtomAxis(2, 0, true);
  molecule.setFrozenAtomAxis(2, 1, true); // atom2: x and y
  molecule.setFrozenAtom(3, true);        // atom3: x, y and z

  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_TRUE(molecule.frozenAtomAxis(0, 0));
  EXPECT_FALSE(molecule.frozenAtomAxis(0, 1));
  EXPECT_TRUE(molecule.frozenAtom(1)); // former atom 3
  EXPECT_TRUE(molecule.frozenAtomAxis(2, 0));
  EXPECT_TRUE(molecule.frozenAtomAxis(2, 1));
  EXPECT_FALSE(molecule.frozenAtomAxis(2, 2));

  molecule.swapAtom(0, 2);
  EXPECT_TRUE(molecule.frozenAtomAxis(0, 0));
  EXPECT_TRUE(molecule.frozenAtomAxis(0, 1));
  EXPECT_TRUE(molecule.frozenAtomAxis(2, 0));
  EXPECT_FALSE(molecule.frozenAtomAxis(2, 1));

  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_FALSE(molecule.frozenAtom(0));
}

TEST_F(MoleculeTest, coordinates3dFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  Array<Vector3> frame0;
  frame0.push_back(Vector3(0, 0, 0));
  frame0.push_back(Vector3(1, 0, 0));
  frame0.push_back(Vector3(2, 0, 0));
  frame0.push_back(Vector3(3, 0, 0));
  molecule.setCoordinate3d(frame0, 0);

  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  Array<Vector3> after = molecule.coordinate3d(0);
  ASSERT_EQ(after.size(), static_cast<size_t>(3));
  EXPECT_EQ(after[0], Vector3(0, 0, 0));
  EXPECT_EQ(after[1], Vector3(3, 0, 0)); // former atom 3
  EXPECT_EQ(after[2], Vector3(2, 0, 0));

  molecule.swapAtom(0, 2);
  after = molecule.coordinate3d(0);
  EXPECT_EQ(after[0], Vector3(2, 0, 0));
  EXPECT_EQ(after[2], Vector3(0, 0, 0));

  // clearAtoms() already drops every stored frame outright.
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(0));
}

TEST_F(MoleculeTest, velocitiesFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  Array<Vector3> vel0;
  vel0.push_back(Vector3(0, 1, 0));
  vel0.push_back(Vector3(1, 1, 0));
  vel0.push_back(Vector3(2, 1, 0));
  vel0.push_back(Vector3(3, 1, 0));
  molecule.setVelocities(vel0, 0);

  // A swap relabels the same structure, so the velocities still describe it.
  molecule.swapAtom(0, 2);
  Array<Vector3> after = molecule.velocities(0);
  ASSERT_EQ(after.size(), static_cast<size_t>(4));
  EXPECT_EQ(after[0], Vector3(2, 1, 0));
  EXPECT_EQ(after[2], Vector3(0, 1, 0));

  // Removing an atom does not: these velocities belong to a geometry that no
  // longer exists, so they are dropped rather than reindexed.
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_TRUE(molecule.velocities(0).empty());

  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_TRUE(molecule.velocities(0).empty());
}

TEST_F(MoleculeTest, vibrationLxFollowsAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  Array<Array<Vector3>> modes(1);
  modes[0].push_back(Vector3(0, 0, 1));
  modes[0].push_back(Vector3(1, 0, 1));
  modes[0].push_back(Vector3(2, 0, 1));
  modes[0].push_back(Vector3(3, 0, 1));
  molecule.setVibrationLx(modes);

  // A swap relabels the same structure, so the modes still describe it.
  molecule.swapAtom(0, 2);
  Array<Vector3> mode0 = molecule.vibrationLx(0);
  ASSERT_EQ(mode0.size(), static_cast<size_t>(4));
  EXPECT_EQ(mode0[0], Vector3(2, 0, 1));
  EXPECT_EQ(mode0[2], Vector3(0, 0, 1));

  // Removing an atom makes the modes meaningless -- they were calculated for
  // a different molecular structure -- so they are dropped, along with the
  // frequencies and intensities that go with them, rather than reindexed.
  molecule.setVibrationFrequencies(Array<double>(1, 1600.0));
  molecule.setVibrationIRIntensities(Array<double>(1, 12.0));
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_EQ(molecule.atomCount(), 3);
  EXPECT_TRUE(molecule.vibrationLx(0).empty());
  EXPECT_TRUE(molecule.vibrationFrequencies().empty());
  EXPECT_TRUE(molecule.vibrationIRIntensities().empty());

  // And with no atoms left there is nothing for modes to describe either.
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_TRUE(molecule.vibrationLx(0).empty());
}

TEST_F(MoleculeTest, vibrationsAreStoredPerConformer)
{
  // A calculation can produce a Hessian at more than one geometry along a
  // path, so the modes belong to a conformer rather than to the molecule.
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  Array<Vector3> first(2, Vector3(0, 0, 0));
  Array<Vector3> second(2, Vector3(0, 0, 1));
  molecule.setCoordinate3d(first, 0);
  molecule.setCoordinate3d(second, 1);

  molecule.setVibrationFrequencies(Array<double>(1, 1600.0), 0);
  molecule.setVibrationFrequencies(Array<double>(1, 1750.0), 1);

  Array<Array<Vector3>> modes0(1, Array<Vector3>(2, Vector3(1, 0, 0)));
  Array<Array<Vector3>> modes1(1, Array<Vector3>(2, Vector3(0, 1, 0)));
  molecule.setVibrationLx(modes0, 0);
  molecule.setVibrationLx(modes1, 1);

  // The unindexed getters are a view onto the active conformer.
  ASSERT_TRUE(molecule.setCoordinate3d(0));
  ASSERT_EQ(molecule.vibrationFrequencies().size(), static_cast<size_t>(1));
  EXPECT_EQ(molecule.vibrationFrequencies()[0], 1600.0);
  EXPECT_EQ(molecule.vibrationLx(0)[0], Vector3(1, 0, 0));

  ASSERT_TRUE(molecule.setCoordinate3d(1));
  ASSERT_EQ(molecule.vibrationFrequencies().size(), static_cast<size_t>(1));
  EXPECT_EQ(molecule.vibrationFrequencies()[0], 1750.0);
  EXPECT_EQ(molecule.vibrationLx(0)[0], Vector3(0, 1, 0));

  // The indexed getters reach any conformer regardless of which is active.
  EXPECT_EQ(molecule.vibrationFrequencies(0)[0], 1600.0);
  EXPECT_EQ(molecule.vibrationLx(0, 0)[0], Vector3(1, 0, 0));

  EXPECT_EQ(molecule.vibrationConformerCount(), static_cast<size_t>(2));
  EXPECT_TRUE(molecule.hasVibrations(0));
  EXPECT_TRUE(molecule.hasVibrations(1));
}

TEST_F(MoleculeTest, conformersWithoutAHessianAreEmptyNotMissing)
{
  // The common case: a trajectory with frequencies only at the converged
  // geometry. Conformers without a Hessian must read as empty rather than
  // returning another conformer's modes or going out of bounds.
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  for (size_t i = 0; i < 4; ++i)
    molecule.setCoordinate3d(Array<Vector3>(2, Vector3(0, 0, 0)), i);

  molecule.setVibrationFrequencies(Array<double>(1, 1600.0), 3);

  EXPECT_EQ(molecule.vibrationConformerCount(), static_cast<size_t>(1));
  ASSERT_EQ(molecule.vibrationConformers().size(), static_cast<size_t>(1));
  EXPECT_EQ(molecule.vibrationConformers()[0], static_cast<size_t>(3));

  ASSERT_TRUE(molecule.setCoordinate3d(1));
  EXPECT_FALSE(molecule.hasVibrations());
  EXPECT_TRUE(molecule.vibrationFrequencies().empty());
  EXPECT_TRUE(molecule.vibrationIRIntensities().empty());
  EXPECT_TRUE(molecule.vibrationLx(0).empty());

  ASSERT_TRUE(molecule.setCoordinate3d(3));
  EXPECT_TRUE(molecule.hasVibrations());
  EXPECT_EQ(molecule.vibrationFrequencies()[0], 1600.0);

  // Out-of-range modes stay empty rather than reading past the end.
  EXPECT_TRUE(molecule.vibrationLx(7).empty());
  EXPECT_TRUE(molecule.vibrationLx(-1).empty());
}

TEST_F(MoleculeTest, vibrationsWithoutConformersUseTheActiveView)
{
  // Several parsers (molden, Gaussian fchk, NWChem) set vibrations on a
  // molecule that has no coordinate sets at all. That has to keep working
  // exactly as it did before vibrations became per-conformer.
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  EXPECT_EQ(molecule.coordinate3dCount(), static_cast<size_t>(0));
  molecule.setVibrationFrequencies(Array<double>(1, 1600.0));
  molecule.setVibrationIRIntensities(Array<double>(1, 12.0));

  EXPECT_TRUE(molecule.hasVibrations());
  ASSERT_EQ(molecule.vibrationFrequencies().size(), static_cast<size_t>(1));
  EXPECT_EQ(molecule.vibrationFrequencies()[0], 1600.0);
  EXPECT_EQ(molecule.vibrationIRIntensities()[0], 12.0);
}

TEST_F(MoleculeTest, swapAtomReindexesEveryConformersModes)
{
  // swapAtom() relabels the same structure, so every conformer's normal mode
  // displacements have to follow their atoms, not just the active one's.
  Molecule molecule;
  for (int i = 0; i < 3; ++i)
    molecule.addAtom(6);

  for (size_t conformer = 0; conformer < 2; ++conformer) {
    Array<Array<Vector3>> modes(1);
    for (int atom = 0; atom < 3; ++atom)
      modes[0].push_back(Vector3(atom, static_cast<double>(conformer), 0));
    molecule.setVibrationLx(modes, conformer);
  }

  molecule.swapAtom(0, 2);

  for (size_t conformer = 0; conformer < 2; ++conformer) {
    Array<Vector3> mode = molecule.vibrationLx(0, conformer);
    ASSERT_EQ(mode.size(), static_cast<size_t>(3));
    EXPECT_EQ(mode[0], Vector3(2, static_cast<double>(conformer), 0));
    EXPECT_EQ(mode[2], Vector3(0, static_cast<double>(conformer), 0));
  }
}

TEST_F(MoleculeTest, clearCoordinate3dKeepsTheActiveConformersModes)
{
  // Flattening a trajectory keeps the geometry on screen, so it keeps the
  // vibrations that belong to that geometry and drops the rest.
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  for (size_t i = 0; i < 3; ++i)
    molecule.setCoordinate3d(Array<Vector3>(2, Vector3(0, 0, 0)), i);

  molecule.setVibrationFrequencies(Array<double>(1, 1600.0), 0);
  molecule.setVibrationFrequencies(Array<double>(1, 1750.0), 2);

  ASSERT_TRUE(molecule.setCoordinate3d(2));
  molecule.clearCoordinate3d();

  EXPECT_EQ(molecule.vibrationConformerCount(), static_cast<size_t>(1));
  ASSERT_EQ(molecule.vibrationFrequencies().size(), static_cast<size_t>(1));
  EXPECT_EQ(molecule.vibrationFrequencies()[0], 1750.0);
}

TEST_F(MoleculeTest, copiedMoleculesKeepEveryConformersModes)
{
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  molecule.setVibrationFrequencies(Array<double>(1, 1600.0), 0);
  molecule.setVibrationFrequencies(Array<double>(1, 1750.0), 1);

  Molecule copy(molecule);
  EXPECT_EQ(copy.vibrationConformerCount(), static_cast<size_t>(2));
  EXPECT_EQ(copy.vibrationFrequencies(1)[0], 1750.0);

  Molecule assigned;
  assigned = molecule;
  EXPECT_EQ(assigned.vibrationConformerCount(), static_cast<size_t>(2));
  EXPECT_EQ(assigned.vibrationFrequencies(1)[0], 1750.0);

  // Moving has to carry the modes across too, not silently drop them.
  Molecule movedFrom(molecule);
  Molecule moveConstructed(std::move(movedFrom));
  EXPECT_EQ(moveConstructed.vibrationConformerCount(), static_cast<size_t>(2));
  EXPECT_EQ(moveConstructed.vibrationFrequencies(1)[0], 1750.0);

  Molecule moveAssignedFrom(molecule);
  Molecule moveAssigned;
  moveAssigned = std::move(moveAssignedFrom);
  EXPECT_EQ(moveAssigned.vibrationConformerCount(), static_cast<size_t>(2));
  EXPECT_EQ(moveAssigned.vibrationFrequencies(1)[0], 1750.0);
}

TEST_F(MoleculeTest, vibrationDataExposesEveryFieldPerConformer)
{
  Molecule molecule;
  for (int i = 0; i < 2; ++i)
    molecule.addAtom(6);

  molecule.setVibrationFrequencies(Array<double>(1, 1600.0), 1);
  molecule.setVibrationIRIntensities(Array<double>(1, 12.0), 1);
  molecule.setVibrationRamanIntensities(Array<double>(1, 3.5), 1);
  Array<Array<Vector3>> modes(1, Array<Vector3>(2, Vector3(0, 0, 1)));
  molecule.setVibrationLx(modes, 1);

  // The indexed accessors read back what was written, for every field.
  EXPECT_EQ(molecule.vibrationIRIntensities(1)[0], 12.0);
  EXPECT_EQ(molecule.vibrationRamanIntensities(1)[0], 3.5);
  EXPECT_EQ(molecule.vibrationLx(0, 1)[0], Vector3(0, 0, 1));

  // A conformer with no data reads as empty rather than as another's.
  EXPECT_TRUE(molecule.vibrationIRIntensities(0).empty());
  EXPECT_TRUE(molecule.vibrationRamanIntensities(0).empty());

  // vibrationData() is the same information in one lookup, and is null for a
  // conformer that has none.
  const Molecule::VibrationData* data = molecule.vibrationData(1);
  ASSERT_NE(data, nullptr);
  EXPECT_FALSE(data->isEmpty());
  EXPECT_EQ(data->frequencies[0], 1600.0);
  EXPECT_EQ(data->irIntensities[0], 12.0);
  EXPECT_EQ(data->ramanIntensities[0], 3.5);
  EXPECT_EQ(data->lx[0][0], Vector3(0, 0, 1));
  EXPECT_EQ(molecule.vibrationData(0), nullptr);

  // clearVibrations() drops every conformer's data, leaving the geometry.
  molecule.clearVibrations();
  EXPECT_EQ(molecule.vibrationConformerCount(), static_cast<size_t>(0));
  EXPECT_FALSE(molecule.hasVibrations(1));
  EXPECT_EQ(molecule.vibrationData(1), nullptr);
  EXPECT_TRUE(molecule.vibrationFrequencies(1).empty());
  EXPECT_EQ(molecule.atomCount(), 2);
}

TEST_F(MoleculeTest, partialChargesFollowTheirAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  MatrixX charges(4, 1);
  charges << 1.0, 2.0, 3.0, 4.0;
  molecule.setPartialCharges("test", charges);

  // swapAtom() must reindex every charge model along with the atoms.
  molecule.swapAtom(0, 2);
  MatrixX swapped = molecule.partialCharges("test");
  ASSERT_EQ(swapped.rows(), 4);
  EXPECT_DOUBLE_EQ(swapped(0, 0), 3.0);
  EXPECT_DOUBLE_EQ(swapped(1, 0), 2.0);
  EXPECT_DOUBLE_EQ(swapped(2, 0), 1.0);
  EXPECT_DOUBLE_EQ(swapped(3, 0), 4.0);

  // removeAtom() deliberately clears partial charges instead of reindexing
  // them: any change to the atom set invalidates cached charge models.
  ASSERT_TRUE(molecule.removeAtom(1));
  EXPECT_TRUE(molecule.partialChargeTypes().empty());

  molecule.setPartialCharges("test2",
                             MatrixX::Constant(molecule.atomCount(), 1, 5.0));
  molecule.clearAtoms();
  molecule.addAtom(6);
  EXPECT_TRUE(molecule.partialChargeTypes().empty());
}

/** Build a molecule carrying a spectrum, for the tests below. */
static Molecule moleculeWithSpectra()
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.addBond(0, 1, 1);
  molecule.addBond(1, 2, 1);
  MatrixX spectrum(2, 2);
  spectrum << 1600.0, 12.0, 3000.0, 40.0;
  molecule.setSpectra("IR", spectrum);
  return molecule;
}

TEST_F(MoleculeTest, spectraDoNotSurviveStructuralEdits)
{
  // A spectrum describes one molecule. Any edit that changes which atoms or
  // bonds exist makes it a different molecule, so the spectrum is dropped
  // rather than left attached to something it does not describe.
  Molecule removingAnAtom = moleculeWithSpectra();
  ASSERT_FALSE(removingAnAtom.spectraTypes().empty());
  ASSERT_TRUE(removingAnAtom.removeAtom(3));
  EXPECT_TRUE(removingAnAtom.spectraTypes().empty());

  Molecule removingABond = moleculeWithSpectra();
  ASSERT_TRUE(removingABond.removeBond(0));
  EXPECT_TRUE(removingABond.spectraTypes().empty());

  Molecule cleared = moleculeWithSpectra();
  cleared.clearAtoms();
  EXPECT_TRUE(cleared.spectraTypes().empty());
}

TEST_F(MoleculeTest, clearBondsKeepsCalculatedResults)
{
  // clearBonds() is "re-perceive connectivity", not a structural edit: the
  // player tool pairs it with perceiveBondsSimple() on every animation frame
  // when dynamic bonding is on. Dropping the vibrations there would destroy
  // the very normal modes being animated, so it must not.
  Molecule molecule = moleculeWithSpectra();
  molecule.setVibrationFrequencies(Array<double>(1, 1600.0));
  Array<Array<Vector3>> modes(1);
  for (int i = 0; i < 4; ++i)
    modes[0].push_back(Vector3(0, 0, 1));
  molecule.setVibrationLx(modes);

  molecule.clearBonds();
  molecule.perceiveBondsSimple();

  EXPECT_FALSE(molecule.spectraTypes().empty());
  EXPECT_FALSE(molecule.vibrationFrequencies().empty());
  EXPECT_EQ(molecule.vibrationLx(0).size(), static_cast<size_t>(4));
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

// --- PropertyMap standalone tests ---

TEST(PropertyMapTest, DoubleProperties)
{
  PropertyMap pm;
  pm.setDouble("charge", 0, -0.3);
  pm.setDouble("charge", 1, 0.15);

  auto val0 = pm.getDouble("charge", 0);
  auto val1 = pm.getDouble("charge", 1);
  ASSERT_TRUE(val0.has_value());
  ASSERT_TRUE(val1.has_value());
  EXPECT_DOUBLE_EQ(*val0, -0.3);
  EXPECT_DOUBLE_EQ(*val1, 0.15);

  // Missing index
  EXPECT_FALSE(pm.getDouble("charge", 5).has_value());
  // Missing name
  EXPECT_FALSE(pm.getDouble("nonexistent", 0).has_value());
}

TEST(PropertyMapTest, IntProperties)
{
  PropertyMap pm;
  pm.setInt("type", 0, 42);
  pm.setInt("type", 2, 7);

  EXPECT_EQ(*pm.getInt("type", 0), 42);
  // Index 1 was auto-filled with sentinel
  EXPECT_FALSE(pm.getInt("type", 1).has_value());
  EXPECT_EQ(*pm.getInt("type", 2), 7);
}

TEST(PropertyMapTest, StringProperties)
{
  PropertyMap pm;
  pm.setString("label", 0, "C.ar");
  pm.setString("label", 1, "N.am");

  EXPECT_EQ(*pm.getString("label", 0), "C.ar");
  EXPECT_EQ(*pm.getString("label", 1), "N.am");
  EXPECT_FALSE(pm.getString("label", 5).has_value());
}

TEST(PropertyMapTest, SparseMatrices)
{
  PropertyMap pm;
  MatrixX tensor(3, 3);
  tensor << 1, 0, 0, 0, 2, 0, 0, 0, 3;
  pm.setMatrix("nmr_tensor", 5, tensor);

  EXPECT_TRUE(pm.hasMatrix("nmr_tensor", 5));
  EXPECT_FALSE(pm.hasMatrix("nmr_tensor", 0));

  auto result = pm.getMatrix("nmr_tensor", 5);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->rows(), 3);
  EXPECT_EQ(result->cols(), 3);
  EXPECT_DOUBLE_EQ((*result)(0, 0), 1.0);
  EXPECT_DOUBLE_EQ((*result)(2, 2), 3.0);

  EXPECT_FALSE(pm.getMatrix("nmr_tensor", 0).has_value());
}

TEST(PropertyMapTest, BulkSetGet)
{
  PropertyMap pm;
  Array<double> charges(3, 0.0);
  charges[0] = -0.3;
  charges[1] = 0.15;
  charges[2] = 0.15;
  pm.setDoubles("charge", charges);

  auto retrieved = pm.doubles("charge");
  EXPECT_EQ(retrieved.size(), 3);
  EXPECT_DOUBLE_EQ(retrieved[0], -0.3);

  // Non-existent column returns empty
  EXPECT_TRUE(pm.doubles("nope").empty());
}

TEST(PropertyMapTest, NameEnumeration)
{
  PropertyMap pm;
  pm.setDouble("charge", 0, 1.0);
  pm.setDouble("spin", 0, 0.5);
  pm.setInt("type", 0, 1);
  pm.setString("label", 0, "C");

  auto dnames = pm.doubleNames();
  EXPECT_EQ(dnames.size(), 2);
  EXPECT_TRUE(dnames.count("charge"));
  EXPECT_TRUE(dnames.count("spin"));
  EXPECT_EQ(pm.intNames().size(), 1);
  EXPECT_EQ(pm.stringNames().size(), 1);
}

TEST(PropertyMapTest, AddEntry)
{
  PropertyMap pm;
  pm.setDouble("charge", 0, 1.0);
  pm.setInt("type", 0, 5);
  pm.addEntry();

  // Column should now be size 2
  auto col = pm.doubles("charge");
  EXPECT_EQ(col.size(), 2);
  // New entry should be sentinel (nullopt via getter)
  EXPECT_FALSE(pm.getDouble("charge", 1).has_value());
  EXPECT_FALSE(pm.getInt("type", 1).has_value());
}

TEST(PropertyMapTest, RemoveEntry)
{
  PropertyMap pm;
  pm.setDouble("charge", 0, 1.0);
  pm.setDouble("charge", 1, 2.0);
  pm.setDouble("charge", 2, 3.0);

  // Remove index 0 (swap with last, then pop)
  pm.removeEntry(0, 3);

  auto col = pm.doubles("charge");
  EXPECT_EQ(col.size(), 2);
  // Index 0 should now have old index 2's value
  EXPECT_DOUBLE_EQ(*pm.getDouble("charge", 0), 3.0);
  EXPECT_DOUBLE_EQ(*pm.getDouble("charge", 1), 2.0);
}

TEST(PropertyMapTest, RemoveEntrySparseMatrix)
{
  PropertyMap pm;
  MatrixX m1(2, 2);
  m1 << 1, 0, 0, 1;
  MatrixX m2(2, 2);
  m2 << 2, 0, 0, 2;

  pm.setMatrix("tensor", 0, m1);
  pm.setMatrix("tensor", 2, m2);

  // Remove index 0 (swap with last index=2, then pop)
  pm.removeEntry(0, 3);

  // m2 (was at index 2) should now be at index 0
  EXPECT_TRUE(pm.hasMatrix("tensor", 0));
  EXPECT_DOUBLE_EQ((*pm.getMatrix("tensor", 0))(0, 0), 2.0);
  EXPECT_FALSE(pm.hasMatrix("tensor", 2));
}

TEST(PropertyMapTest, SwapEntries)
{
  PropertyMap pm;
  pm.setDouble("charge", 0, 1.0);
  pm.setDouble("charge", 1, 2.0);

  pm.swapEntries(0, 1, 2);
  EXPECT_DOUBLE_EQ(*pm.getDouble("charge", 0), 2.0);
  EXPECT_DOUBLE_EQ(*pm.getDouble("charge", 1), 1.0);
}

TEST(PropertyMapTest, Clear)
{
  PropertyMap pm;
  pm.setDouble("a", 0, 1.0);
  pm.setInt("b", 0, 2);
  pm.setString("c", 0, "x");
  EXPECT_FALSE(pm.empty());

  pm.clear();
  EXPECT_TRUE(pm.empty());
  EXPECT_TRUE(pm.doubleNames().empty());
}

// --- Molecule integration tests ---

TEST_F(MoleculeTest, AtomProperties)
{
  m_testMolecule.atomProperties().setDouble("charge", 0, -0.3);
  m_testMolecule.atomProperties().setDouble("charge", 1, 0.15);
  m_testMolecule.atomProperties().setDouble("charge", 2, 0.15);

  EXPECT_DOUBLE_EQ(*m_testMolecule.atomProperties().getDouble("charge", 0),
                   -0.3);
  EXPECT_DOUBLE_EQ(*m_testMolecule.atomProperties().getDouble("charge", 2),
                   0.15);
}

TEST_F(MoleculeTest, AtomProxyProperties)
{
  Atom o1 = m_testMolecule.atom(0);
  o1.setProperty("spin_density", 0.42);
  o1.setProperty("type_index", 3);
  o1.setProperty("symmetry_label", std::string("C2v"));

  auto spin = o1.property<double>("spin_density");
  ASSERT_TRUE(spin.has_value());
  EXPECT_DOUBLE_EQ(*spin, 0.42);

  auto typeIdx = o1.property<int>("type_index");
  ASSERT_TRUE(typeIdx.has_value());
  EXPECT_EQ(*typeIdx, 3);

  auto symLabel = o1.property<std::string>("symmetry_label");
  ASSERT_TRUE(symLabel.has_value());
  EXPECT_EQ(*symLabel, "C2v");

  // Wrong type returns nullopt
  EXPECT_FALSE(o1.property<int>("spin_density").has_value());
  EXPECT_FALSE(o1.property<double>("symmetry_label").has_value());

  // Numeric to string conversion
  auto spinStr = o1.property<std::string>("spin_density");
  ASSERT_TRUE(spinStr.has_value());
  // Should be a string representation of 0.42
  EXPECT_NE(spinStr->find("0.42"), std::string::npos);
}

TEST_F(MoleculeTest, BondProxyProperties)
{
  Bond b = m_testMolecule.bond(0);
  b.setProperty("wiberg_index", 0.95);

  auto wi = b.property<double>("wiberg_index");
  ASSERT_TRUE(wi.has_value());
  EXPECT_DOUBLE_EQ(*wi, 0.95);
}

TEST_F(MoleculeTest, AtomPropertyMatrices)
{
  Atom o1 = m_testMolecule.atom(0);
  MatrixX tensor(3, 3);
  tensor << 1, 2, 3, 4, 5, 6, 7, 8, 9;
  o1.setProperty("nmr_tensor", tensor);

  auto result = o1.property<MatrixX>("nmr_tensor");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->rows(), 3);
  EXPECT_DOUBLE_EQ((*result)(1, 1), 5.0);

  // Other atoms don't have it
  Atom h2 = m_testMolecule.atom(1);
  EXPECT_FALSE(h2.property<MatrixX>("nmr_tensor").has_value());
}

TEST_F(MoleculeTest, RemoveAtomPreservesProperties)
{
  // Set properties on all 3 atoms (water: O, H, H)
  m_testMolecule.atomProperties().setDouble("charge", 0, -0.8);
  m_testMolecule.atomProperties().setDouble("charge", 1, 0.4);
  m_testMolecule.atomProperties().setDouble("charge", 2, 0.4);

  // Remove atom 0 (oxygen) — swap-and-pop with atom 2
  m_testMolecule.removeAtom(0);

  EXPECT_EQ(m_testMolecule.atomCount(), 2);
  // Index 0 should now have old atom 2's charge
  auto charge0 = m_testMolecule.atomProperties().getDouble("charge", 0);
  ASSERT_TRUE(charge0.has_value());
  EXPECT_DOUBLE_EQ(*charge0, 0.4);
}

TEST_F(MoleculeTest, CopyMoleculePreservesProperties)
{
  m_testMolecule.atomProperties().setDouble("charge", 0, -0.3);
  m_testMolecule.bondProperties().setDouble("wiberg", 0, 0.95);

  Molecule copy(m_testMolecule);

  EXPECT_DOUBLE_EQ(*copy.atomProperties().getDouble("charge", 0), -0.3);
  EXPECT_DOUBLE_EQ(*copy.bondProperties().getDouble("wiberg", 0), 0.95);

  // Modify copy, verify original unchanged (COW)
  copy.atomProperties().setDouble("charge", 0, 999.0);
  EXPECT_DOUBLE_EQ(*m_testMolecule.atomProperties().getDouble("charge", 0),
                   -0.3);
}

TEST_F(MoleculeTest, ConformerProperties)
{
  // Set up two conformers
  Array<Vector3> coords1(3, Vector3::Zero());
  Array<Vector3> coords2(3, Vector3::Zero());
  m_testMolecule.setCoordinate3d(coords1, 0);
  m_testMolecule.setCoordinate3d(coords2, 1);

  // Store per-conformer energies
  m_testMolecule.conformerProperties().setDouble("energy", 0, -75.5);
  m_testMolecule.conformerProperties().setDouble("energy", 1, -74.2);

  auto e0 = m_testMolecule.conformerProperties().getDouble("energy", 0);
  auto e1 = m_testMolecule.conformerProperties().getDouble("energy", 1);
  ASSERT_TRUE(e0.has_value());
  ASSERT_TRUE(e1.has_value());
  EXPECT_DOUBLE_EQ(*e0, -75.5);
  EXPECT_DOUBLE_EQ(*e1, -74.2);

  // Store per-conformer forces as MatrixX (atomCount x 3)
  MatrixX forces(3, 3);
  forces << 0.1, 0.2, 0.3, -0.1, -0.2, -0.3, 0.0, 0.0, 0.0;
  m_testMolecule.conformerProperties().setMatrix("forces", 0, forces);

  auto f0 = m_testMolecule.conformerProperties().getMatrix("forces", 0);
  ASSERT_TRUE(f0.has_value());
  EXPECT_EQ(f0->rows(), 3);
  EXPECT_EQ(f0->cols(), 3);
  EXPECT_DOUBLE_EQ((*f0)(0, 0), 0.1);

  // Conformer 1 has no forces
  EXPECT_FALSE(m_testMolecule.conformerProperties().hasMatrix("forces", 1));

  // clearCoordinate3d should clear conformer properties
  m_testMolecule.clearCoordinate3d();
  EXPECT_TRUE(m_testMolecule.conformerProperties().empty());
}

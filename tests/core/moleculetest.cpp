/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "utils.h"

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <type_traits>

#include <limits>
#include <random>

#include <avogadro/core/array.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/constraint.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
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

// Molecule's move operations move m_data rather than copying it. VariantMap
// declares a defaulted destructor, which suppresses its implicit move
// constructor unless the moves are declared too -- and if that regresses,
// std::move(m_data) silently becomes a copy again with nothing to flag it.
//
// Compare VariantMap against the map it wraps rather than asserting noexcept
// outright. Whether std::map's move is noexcept is an implementation choice --
// libc++ and libstdc++ say yes, MSVC does not -- so an absolute assertion here
// would be testing the standard library rather than this class. If VariantMap
// loses its move constructor it falls back to copying the map, which allocates
// and so is never noexcept, and the two sides stop matching.
namespace {
using VariantMapStorage = std::map<std::string, Variant>;
} // namespace

static_assert(std::is_nothrow_move_constructible<VariantMap>::value ==
                std::is_nothrow_move_constructible<VariantMapStorage>::value,
              "VariantMap no longer moves as well as the map it wraps: a "
              "user-declared destructor has suppressed its move constructor, "
              "so Molecule's move constructor is silently copying m_data.");
static_assert(std::is_nothrow_move_assignable<VariantMap>::value ==
                std::is_nothrow_move_assignable<VariantMapStorage>::value,
              "VariantMap no longer moves as well as the map it wraps: a "
              "user-declared destructor has suppressed its move assignment, "
              "so Molecule's move assignment is silently copying m_data.");

TEST_F(MoleculeTest, moveTransfersDataAndSpectra)
{
  Molecule original;
  original.addAtom(6);
  original.setData("name", Variant(std::string("ethane")));
  MatrixX ir(2, 2);
  ir << 1.0, 2.0, 3.0, 4.0;
  original.setSpectra("IR", ir);
  original.addConstraint(1.5, 0, 0);

  Molecule moved(std::move(original));

  EXPECT_EQ(moved.data("name").toString(), "ethane");
  EXPECT_TRUE(moved.spectra("IR").isApprox(ir));
  EXPECT_EQ(moved.constraints().size(), 1u);
}

TEST_F(MoleculeTest, moveAssignTransfersDataAndSpectra)
{
  Molecule original;
  original.addAtom(6);
  original.setData("name", Variant(std::string("ethane")));
  MatrixX ir(2, 2);
  ir << 1.0, 2.0, 3.0, 4.0;
  original.setSpectra("IR", ir);

  Molecule target;
  target.addAtom(8);
  target.setData("name", Variant(std::string("water")));

  target = std::move(original);

  EXPECT_EQ(target.data("name").toString(), "ethane");
  EXPECT_TRUE(target.spectra("IR").isApprox(ir));
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

// Residues are residue-indexed, not atom-indexed, but the Atom proxies in
// their name maps carry atom indices. swapAtom() has to reindex those too, or
// a residue keeps the names and silently adopts whichever atoms land on the
// old indices.
TEST_F(MoleculeTest, SwapAtomReindexesResidues)
{
  Avogadro::Core::Molecule molecule;
  molecule.addAtom(7).setPosition3d(Avogadro::Vector3(0.0, 0.0, 0.0)); // N
  molecule.addAtom(6).setPosition3d(Avogadro::Vector3(1.5, 0.0, 0.0)); // CA
  molecule.addAtom(8).setPosition3d(Avogadro::Vector3(2.5, 1.0, 0.0)); // O

  std::string resName = "ALA";
  Avogadro::Index resNumber = 1;
  char chain = 'A';
  Avogadro::Core::Residue& residue =
    molecule.addResidue(resName, resNumber, chain);
  residue.addResidueAtom("N", molecule.atom(0));
  residue.addResidueAtom("CA", molecule.atom(1));
  residue.addResidueAtom("O", molecule.atom(2));

  molecule.swapAtom(0, 2);

  // Each name must still resolve to the atom it was given, which is now at a
  // different index and is identified here by its element.
  const Avogadro::Core::Residue& swapped = molecule.residue(0);
  EXPECT_EQ(static_cast<Avogadro::Index>(2), swapped.atomByName("N").index());
  EXPECT_EQ(7, swapped.atomByName("N").atomicNumber());
  EXPECT_EQ(static_cast<Avogadro::Index>(1), swapped.atomByName("CA").index());
  EXPECT_EQ(6, swapped.atomByName("CA").atomicNumber());
  EXPECT_EQ(static_cast<Avogadro::Index>(0), swapped.atomByName("O").index());
  EXPECT_EQ(8, swapped.atomByName("O").atomicNumber());

  // Swapping back restores the original numbering.
  molecule.swapAtom(0, 2);
  EXPECT_EQ(static_cast<Avogadro::Index>(0),
            molecule.residue(0).atomByName("N").index());
  EXPECT_EQ(static_cast<Avogadro::Index>(2),
            molecule.residue(0).atomByName("O").index());
}

// An atom outside the residue must not be dragged into it by a swap.
TEST_F(MoleculeTest, SwapAtomLeavesUnrelatedAtomsOutOfResidues)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(static_cast<unsigned char>(6 + i));

  std::string resName = "LIG";
  Avogadro::Index resNumber = 1;
  char chain = 'A';
  Avogadro::Core::Residue& residue =
    molecule.addResidue(resName, resNumber, chain);
  residue.addResidueAtom("C1", molecule.atom(0));

  // Atom 3 belongs to no residue; swapping it with the residue's only atom
  // must move the membership, not duplicate or drop it.
  molecule.swapAtom(0, 3);

  const Avogadro::Core::Residue& swapped = molecule.residue(0);
  EXPECT_EQ(static_cast<size_t>(1), swapped.residueAtoms().size());
  EXPECT_EQ(static_cast<Avogadro::Index>(3), swapped.atomByName("C1").index());
  EXPECT_EQ(6, swapped.atomByName("C1").atomicNumber());
}

// Constraints name atoms by index without being atom-indexed themselves, so
// swapAtom() has to reindex them or a constraint silently starts restraining
// different atoms.
TEST_F(MoleculeTest, SwapAtomReindexesConstraints)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(static_cast<unsigned char>(6 + i));

  // A distance constraint on atoms 0-1, and a torsion on 0-1-2-3.
  molecule.addConstraint(1.5, 0, 1);
  molecule.addConstraint(60.0, 0, 1, 2, 3);

  molecule.swapAtom(0, 4);

  const auto& distance = molecule.constraints()[0];
  EXPECT_EQ(static_cast<Avogadro::Index>(4), distance.aIndex());
  EXPECT_EQ(static_cast<Avogadro::Index>(1), distance.bIndex());
  EXPECT_EQ(1.5, distance.value());
  // An unused reference stays unused rather than being reindexed onto an atom.
  EXPECT_EQ(Avogadro::MaxIndex, distance.cIndex());
  EXPECT_EQ(Avogadro::MaxIndex, distance.dIndex());
  EXPECT_EQ(Avogadro::Core::Constraint::DistanceConstraint, distance.type());

  const auto& torsion = molecule.constraints()[1];
  EXPECT_EQ(static_cast<Avogadro::Index>(4), torsion.aIndex());
  EXPECT_EQ(static_cast<Avogadro::Index>(1), torsion.bIndex());
  EXPECT_EQ(static_cast<Avogadro::Index>(2), torsion.cIndex());
  EXPECT_EQ(static_cast<Avogadro::Index>(3), torsion.dIndex());
  EXPECT_EQ(60.0, torsion.value());
  EXPECT_EQ(Avogadro::Core::Constraint::TorsionConstraint, torsion.type());

  // A swap between two atoms a constraint names must exchange them, not drop
  // one of them.
  molecule.swapAtom(1, 2);
  const auto& swapped = molecule.constraints()[1];
  EXPECT_EQ(static_cast<Avogadro::Index>(2), swapped.bIndex());
  EXPECT_EQ(static_cast<Avogadro::Index>(1), swapped.cIndex());
}

// A basis set records which atom each basis function sits on. Renumbering
// atoms under a wavefunction has to carry those references across, or the
// orbitals are silently attributed to the wrong nuclei.
TEST_F(MoleculeTest, SwapAtomReindexesGaussianBasis)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 3; ++i)
    molecule.addAtom(static_cast<unsigned char>(6 + i));

  auto* basis = new Avogadro::Core::GaussianSet;
  basis->setMolecule(&molecule);
  // One shell on atom 0, two on atom 2, one on atom 1.
  basis->addBasis(0, Avogadro::Core::GaussianSet::S);
  basis->addBasis(2, Avogadro::Core::GaussianSet::S);
  basis->addBasis(2, Avogadro::Core::GaussianSet::P);
  basis->addBasis(1, Avogadro::Core::GaussianSet::S);
  molecule.setBasisSet(basis);

  molecule.swapAtom(0, 2);

  // Shell order is untouched -- only the atom each shell names moves, which
  // is what keeps MO coefficients valid.
  const std::vector<unsigned int> expected = { 2, 0, 0, 1 };
  EXPECT_EQ(expected, basis->atomIndices());
}

// Normal mode displacements are stored per mode per atom, so they have to
// follow their atom through a renumbering.
TEST_F(MoleculeTest, SwapAtomCarriesVibrationalDisplacements)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 3; ++i)
    molecule.addAtom(static_cast<unsigned char>(6 + i));

  Avogadro::Core::Array<double> frequencies;
  frequencies.push_back(1000.0);
  frequencies.push_back(2000.0);
  molecule.setVibrationFrequencies(frequencies);

  // Two modes, each giving atom i the displacement (i, 0, 0) or (0, i, 0).
  Avogadro::Core::Array<Avogadro::Core::Array<Avogadro::Vector3>> lx;
  for (int mode = 0; mode < 2; ++mode) {
    Avogadro::Core::Array<Avogadro::Vector3> displacements;
    for (int i = 0; i < 3; ++i)
      displacements.push_back(mode == 0 ? Avogadro::Vector3(i, 0.0, 0.0)
                                        : Avogadro::Vector3(0.0, i, 0.0));
    lx.push_back(displacements);
  }
  molecule.setVibrationLx(lx);

  molecule.swapAtom(0, 2);

  // Atom 0's displacement is now at index 2, and vice versa, in every mode.
  const Avogadro::Core::Array<Avogadro::Vector3> mode0 =
    molecule.vibrationLx(0);
  const Avogadro::Core::Array<Avogadro::Vector3> mode1 =
    molecule.vibrationLx(1);
  ASSERT_EQ(static_cast<size_t>(3), mode0.size());
  EXPECT_EQ(Avogadro::Vector3(2.0, 0.0, 0.0), mode0[0]);
  EXPECT_EQ(Avogadro::Vector3(0.0, 0.0, 0.0), mode0[2]);
  EXPECT_EQ(Avogadro::Vector3(0.0, 2.0, 0.0), mode1[0]);
  EXPECT_EQ(Avogadro::Vector3(0.0, 0.0, 0.0), mode1[2]);
  // The frequencies are mode-indexed and must not move.
  ASSERT_EQ(static_cast<size_t>(2), molecule.vibrationFrequencies().size());
  EXPECT_EQ(1000.0, molecule.vibrationFrequencies()[0]);
}

TEST_F(MoleculeTest, scanCoordinatesFollowTheirAtoms)
{
  // Scan coordinates name atoms by index, like constraints, but are stored in
  // the property map, so none of the per-atom bookkeeping reaches them. A
  // stale index measures whatever atom lands in that slot and plots a
  // believable curve for the wrong thing.
  Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(6);

  molecule.addScanCoordinate(Avogadro::Core::Constraint(0, 4));
  molecule.addScanCoordinate(Avogadro::Core::Constraint(1, 2, 3));

  // A swap only relabels the structure, so both coordinates survive it.
  molecule.swapAtom(0, 3);
  std::vector<Avogadro::Core::Constraint> coordinates =
    molecule.scanCoordinates();
  ASSERT_EQ(coordinates.size(), 2u);
  EXPECT_EQ(coordinates[0].aIndex(), 3u);
  EXPECT_EQ(coordinates[0].bIndex(), 4u);
  EXPECT_EQ(coordinates[1].aIndex(), 1u);
  EXPECT_EQ(coordinates[1].bIndex(), 2u);
  EXPECT_EQ(coordinates[1].cIndex(), 0u);
  // Unused slots must stay unused, or the type changes.
  EXPECT_EQ(coordinates[0].cIndex(), Avogadro::MaxIndex);
  EXPECT_EQ(coordinates[0].type(),
            Avogadro::Core::Constraint::DistanceConstraint);
  EXPECT_EQ(coordinates[1].type(), Avogadro::Core::Constraint::AngleConstraint);
}

TEST_F(MoleculeTest, scanCoordinatesDropTheirRemovedAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(6);

  molecule.addScanCoordinate(Avogadro::Core::Constraint(0, 1)); // untouched
  molecule.addScanCoordinate(Avogadro::Core::Constraint(2, 4)); // names both
  molecule.addScanCoordinate(Avogadro::Core::Constraint(0, 1, 2, 3));

  // removeAtom() swaps the last atom into the hole, so a coordinate naming
  // atom 4 has to follow it to index 2, and one naming atom 2 is gone.
  ASSERT_TRUE(molecule.removeAtom(2));
  EXPECT_EQ(molecule.atomCount(), 4);

  std::vector<Avogadro::Core::Constraint> coordinates =
    molecule.scanCoordinates();
  ASSERT_EQ(coordinates.size(), 1u);
  EXPECT_EQ(coordinates[0].aIndex(), 0u);
  EXPECT_EQ(coordinates[0].bIndex(), 1u);

  // Every surviving index still has to name a real atom.
  for (const auto& coordinate : coordinates)
    EXPECT_TRUE(coordinate.isValid(molecule.atomCount()));
}

TEST_F(MoleculeTest, scanCoordinatesFollowTheSwappedInAtom)
{
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.addScanCoordinate(Avogadro::Core::Constraint(0, 3));

  // Atom 3 lands at index 1, so the coordinate must now read 0-1.
  ASSERT_TRUE(molecule.removeAtom(1));
  std::vector<Avogadro::Core::Constraint> coordinates =
    molecule.scanCoordinates();
  ASSERT_EQ(coordinates.size(), 1u);
  EXPECT_EQ(coordinates[0].aIndex(), 0u);
  EXPECT_EQ(coordinates[0].bIndex(), 1u);
}

TEST_F(MoleculeTest, scanCoordinatesGoWithTheAtoms)
{
  Molecule molecule;
  for (int i = 0; i < 3; ++i)
    molecule.addAtom(6);
  molecule.addScanCoordinate(Avogadro::Core::Constraint(0, 1, 2));

  // Whatever atoms are added next are not the ones that were measured.
  molecule.clearAtoms();
  EXPECT_TRUE(molecule.scanCoordinates().empty());

  for (int i = 0; i < 3; ++i)
    molecule.addAtom(8);
  EXPECT_TRUE(molecule.scanCoordinates().empty());
}

TEST_F(MoleculeTest, scanCoordinatesRejectValuesThatAreNotAtomIndices)
{
  // The property map holds doubles, and the matrix can arrive from a file
  // rather than from setScanCoordinates(). A fractional or absurd value must
  // not be rounded or cast into some unrelated atom.
  Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  MatrixX matrix(4, 4);
  matrix << 0.0, 1.0, -1.0, -1.0, // usable
    2.5, 1.0, -1.0, -1.0,         // fractional
    0.0, 1.0e300, -1.0, -1.0,     // far outside Index
    0.0, std::numeric_limits<double>::quiet_NaN(), -1.0, -1.0;
  molecule.setData("scanCoordinates", matrix);

  std::vector<Avogadro::Core::Constraint> coordinates =
    molecule.scanCoordinates();
  ASSERT_EQ(coordinates.size(), 1u);
  EXPECT_EQ(coordinates[0].aIndex(), 0u);
  EXPECT_EQ(coordinates[0].bIndex(), 1u);
}

TEST_F(MoleculeTest, RemoveAtomDropsConstraintsThatLoseAnAtom)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(6);

  molecule.addConstraint(1.5, 0, 1);        // untouched by the removal
  molecule.addConstraint(1.4, 2, 3);        // names the atom being removed
  molecule.addConstraint(60.0, 0, 1, 2, 3); // also names it

  // Removing atom 2 leaves only the constraint that never mentioned it. A
  // constraint that lost an atom must go rather than be shortened onto the
  // atoms that remain: an optimizer would hold that different coordinate just
  // as stiffly as the one actually asked for.
  ASSERT_TRUE(molecule.removeAtom(2));
  ASSERT_EQ(molecule.constraints().size(), 1u);

  const auto& kept = molecule.constraints()[0];
  EXPECT_EQ(kept.aIndex(), static_cast<Avogadro::Index>(0));
  EXPECT_EQ(kept.bIndex(), static_cast<Avogadro::Index>(1));
  EXPECT_EQ(kept.value(), 1.5);
  EXPECT_EQ(kept.type(), Avogadro::Core::Constraint::DistanceConstraint);
}

TEST_F(MoleculeTest, RemoveAtomFollowsTheSwappedInConstraintAtom)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);

  molecule.addConstraint(1.5, 0, 3);
  molecule.constraints()[0].setK(500.0);

  // removeAtom() swaps the last atom into the hole, so the constraint on atom
  // 3 now holds atom 1. Left alone it would hold whatever landed there.
  ASSERT_TRUE(molecule.removeAtom(1));
  ASSERT_EQ(molecule.constraints().size(), 1u);

  const auto& moved = molecule.constraints()[0];
  EXPECT_EQ(moved.aIndex(), static_cast<Avogadro::Index>(0));
  EXPECT_EQ(moved.bIndex(), static_cast<Avogadro::Index>(1));
  // The restraint itself is unchanged: same target, same force constant.
  EXPECT_EQ(moved.value(), 1.5);
  EXPECT_EQ(moved.k(), 500.0);
  EXPECT_EQ(moved.type(), Avogadro::Core::Constraint::DistanceConstraint);

  // And every surviving reference still names a real atom.
  EXPECT_TRUE(moved.isValid(molecule.atomCount()));
}

TEST_F(MoleculeTest, RemoveAtomKeepsAnExplicitConstraintType)
{
  // An out-of-plane constraint has the same four references as a torsion, so
  // its type cannot be inferred and must survive the reindexing.
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 5; ++i)
    molecule.addAtom(6);

  molecule.addConstraint(10.0, 0, 1, 2, 4);
  molecule.constraints()[0].setType(
    Avogadro::Core::Constraint::OutOfPlaneConstraint);

  ASSERT_TRUE(molecule.removeAtom(3));
  ASSERT_EQ(molecule.constraints().size(), 1u);
  EXPECT_EQ(molecule.constraints()[0].dIndex(),
            static_cast<Avogadro::Index>(3));
  EXPECT_EQ(molecule.constraints()[0].type(),
            Avogadro::Core::Constraint::OutOfPlaneConstraint);
}

TEST_F(MoleculeTest, ClearAtomsClearsConstraints)
{
  Avogadro::Core::Molecule molecule;
  for (int i = 0; i < 4; ++i)
    molecule.addAtom(6);
  molecule.addConstraint(1.5, 0, 1);
  molecule.addConstraint(60.0, 0, 1, 2, 3);

  // Whatever atoms are added next are not the ones that were constrained.
  molecule.clearAtoms();
  EXPECT_TRUE(molecule.constraints().empty());

  for (int i = 0; i < 4; ++i)
    molecule.addAtom(8);
  EXPECT_TRUE(molecule.constraints().empty());
}

// Three geometries a fixed distance apart, with the timing supplied by the
// caller rather than stored on the molecule -- which is the usual case, since
// hardly any trajectory format records when each frame was written.
TEST_F(MoleculeTest, estimateVelocitiesUniformTimeStep)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);

  for (int i = 0; i < 3; ++i) {
    Array<Vector3> coords;
    coords.push_back(Vector3(i, 0.0, 0.0));
    coords.push_back(Vector3(i + 1.0, 0.0, 0.0));
    molecule.setCoordinate3d(coords, i);
  }

  // No timesteps stored, so the no-argument overload has nothing to work with.
  molecule.estimateVelocities();
  EXPECT_TRUE(molecule.velocities(0).empty());

  // 1 Angstrom every 0.5 ps is 2 Angstrom/ps.
  molecule.estimateVelocities(0.5);

  for (int i = 0; i < 3; ++i) {
    Array<Vector3> v = molecule.velocities(i);
    ASSERT_EQ(v.size(), static_cast<size_t>(2));
    EXPECT_NEAR(v[0].x(), 2.0, 1e-9);
    EXPECT_NEAR(v[1].x(), 2.0, 1e-9);
  }

  // The per-coordinate-set scalars land in the property map next to
  // "energies" and "forces".
  ASSERT_TRUE(molecule.hasData("velocities"));
  std::vector<double> speeds = molecule.data("velocities").toList();
  ASSERT_EQ(speeds.size(), static_cast<size_t>(3));
  for (double speed : speeds)
    EXPECT_NEAR(speed, 2.0, 1e-9);

  // Both atoms move alike, so there is no spread in their speeds.
  std::vector<double> deviations = molecule.data("velocityDeviations").toList();
  ASSERT_EQ(deviations.size(), static_cast<size_t>(3));
  for (double deviation : deviations)
    EXPECT_NEAR(deviation, 0.0, 1e-9);

  // ... and the motion is pure translation of the whole molecule, which is
  // drift rather than heat, so the temperature is zero.
  std::vector<double> temperatures = molecule.data("temperatures").toList();
  ASSERT_EQ(temperatures.size(), static_cast<size_t>(3));
  for (double temperature : temperatures)
    EXPECT_NEAR(temperature, 0.0, 1e-9);
}

// Two hydrogens flying apart along x at the same speed: the center of mass
// stays put, so all of the kinetic energy is thermal.
TEST_F(MoleculeTest, estimateVelocitiesTemperature)
{
  const double speed = 19.0; // Angstrom/ps
  const double dt = 0.25;    // ps

  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);

  Array<Vector3> coords0;
  coords0.push_back(Vector3(0.0, 0.0, 0.0));
  coords0.push_back(Vector3(2.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords0, 0);

  Array<Vector3> coords1;
  coords1.push_back(Vector3(-speed * dt, 0.0, 0.0));
  coords1.push_back(Vector3(2.0 + speed * dt, 0.0, 0.0));
  molecule.setCoordinate3d(coords1, 1);

  molecule.estimateVelocities(dt);

  Array<Vector3> v = molecule.velocities(1);
  ASSERT_EQ(v.size(), static_cast<size_t>(2));
  EXPECT_NEAR(v[0].x(), -speed, 1e-9);
  EXPECT_NEAR(v[1].x(), speed, 1e-9);

  // T = 2 KE / (N_df k_B), with KE = 1/2 sum m v^2 = m * speed^2 here, three
  // degrees of freedom left after the center-of-mass translation is removed,
  // and k_B = 0.831446261815324 amu A^2 / (ps^2 K).
  const double mass = Avogadro::Core::Elements::mass(1);
  const double expected =
    2.0 * (mass * speed * speed) / (3.0 * 0.831446261815324);

  std::vector<double> temperatures = molecule.data("temperatures").toList();
  ASSERT_EQ(temperatures.size(), static_cast<size_t>(2));
  EXPECT_NEAR(temperatures[1], expected, 1e-6);
  // The first set takes a forward difference over the same pair of geometries.
  EXPECT_NEAR(temperatures[0], expected, 1e-6);

  std::vector<double> speeds = molecule.data("velocities").toList();
  ASSERT_EQ(speeds.size(), static_cast<size_t>(2));
  EXPECT_NEAR(speeds[1], speed, 1e-9);
}

// The spread of the atomic speeds is what the plot's error bars show, so it
// has to follow the distribution rather than the average.
TEST_F(MoleculeTest, estimateVelocitiesSpeedSpread)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);

  Array<Vector3> coords0;
  coords0.push_back(Vector3(0.0, 0.0, 0.0));
  coords0.push_back(Vector3(5.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords0, 0);

  Array<Vector3> coords1;
  coords1.push_back(Vector3(-1.0, 0.0, 0.0)); // 1 Angstrom/ps
  coords1.push_back(Vector3(8.0, 0.0, 0.0));  // 3 Angstrom/ps
  molecule.setCoordinate3d(coords1, 1);

  molecule.estimateVelocities(1.0);

  // Speeds of 1 and 3: mean 2, population standard deviation 1.
  std::vector<double> speeds = molecule.data("velocities").toList();
  std::vector<double> deviations = molecule.data("velocityDeviations").toList();
  ASSERT_EQ(speeds.size(), static_cast<size_t>(2));
  ASSERT_EQ(deviations.size(), static_cast<size_t>(2));
  EXPECT_NEAR(speeds[1], 2.0, 1e-9);
  EXPECT_NEAR(deviations[1], 1.0, 1e-9);
}

// A single geometry is not a trajectory, and must not leave stale scalars
// behind for something else to plot.
TEST_F(MoleculeTest, estimateVelocitiesSingleGeometry)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);

  Array<Vector3> coords;
  coords.push_back(Vector3(0.0, 0.0, 0.0));
  coords.push_back(Vector3(1.0, 0.0, 0.0));
  molecule.setCoordinate3d(coords, 0);

  molecule.estimateVelocities(1.0);

  EXPECT_TRUE(molecule.velocities(0).empty());
  EXPECT_TRUE(molecule.data("velocities").toList().empty());
  EXPECT_TRUE(molecule.data("temperatures").toList().empty());
}

// A labelled atom weighs what its isotope weighs, which is the difference
// between the right temperature and one several percent out.
TEST_F(MoleculeTest, estimateVelocitiesTemperatureUsesIsotopeMasses)
{
  const double speed = 19.0; // Angstrom/ps
  const double dt = 0.25;    // ps

  const auto build = [speed, dt](unsigned short isotope) {
    Molecule molecule;
    molecule.addAtom(1);
    molecule.addAtom(1);
    if (isotope > 0) {
      molecule.setIsotope(0, isotope);
      molecule.setIsotope(1, isotope);
    }

    Array<Vector3> coords0;
    coords0.push_back(Vector3(0.0, 0.0, 0.0));
    coords0.push_back(Vector3(2.0, 0.0, 0.0));
    molecule.setCoordinate3d(coords0, 0);

    Array<Vector3> coords1;
    coords1.push_back(Vector3(-speed * dt, 0.0, 0.0));
    coords1.push_back(Vector3(2.0 + speed * dt, 0.0, 0.0));
    molecule.setCoordinate3d(coords1, 1);

    molecule.estimateVelocities(dt);
    return molecule.data("temperatures").toList()[1];
  };

  const double hydrogen = build(0);
  const double deuterium = build(2);

  // The kinetic energy is linear in the mass, so deuterium at the same speed
  // is hotter by exactly the mass ratio.
  const double ratio = Avogadro::Core::Elements::isotopeMass(1, 2) /
                       Avogadro::Core::Elements::mass(1);
  EXPECT_GT(ratio, 1.9);
  EXPECT_NEAR(deuterium, hydrogen * ratio, 1e-6);
}

// An atom added after the position arrays were filled has an index past the
// end of them while they are still non-empty. position3d() used to guard only
// on the arrays being non-empty, so it indexed straight past the end -- an
// out-of-bounds read reached from centerOfGeometry(), centerOfMass(),
// radius() and anything else that walks atomCount().
//
// Found by the Windows fuzz job, core/molecule, on a one-byte input: ten
// atoms with positions, then one more atom appended without one.
//
// The force array is not exposed the same way -- addAtom() runs
// clearCalculatedResults(), which empties it -- but forceVector() carried the
// identical guard, so it is checked here too.
TEST_F(MoleculeTest, atomWithoutPosition)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.setAtomPosition3d(0, Vector3(1.0, 2.0, 3.0));
  molecule.setAtomPosition2d(0, Vector2(1.0, 2.0));

  Array<Vector3> forces;
  forces.push_back(Vector3(0.5, 0.5, 0.5));
  ASSERT_TRUE(molecule.setForceVectors(forces));
  EXPECT_EQ(molecule.atom(0).forceVector(), Vector3(0.5, 0.5, 0.5));

  // Every array is now exactly as long as the molecule. Appending an atom
  // leaves the position arrays one short, which is the state that used to
  // read off the end.
  molecule.addAtom(6);

  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(2));
  ASSERT_EQ(molecule.atomPositions3d().size(), static_cast<size_t>(1));
  ASSERT_EQ(molecule.atomPositions2d().size(), static_cast<size_t>(1));

  EXPECT_EQ(molecule.atom(0).position3d(), Vector3(1.0, 2.0, 3.0));
  EXPECT_EQ(molecule.atom(0).position2d(), Vector2(1.0, 2.0));

  // The atom with no position reads as the origin rather than off the end.
  EXPECT_EQ(molecule.atom(1).position3d(), Vector3::Zero());
  EXPECT_EQ(molecule.atom(1).position2d(), Vector2::Zero());

  // These walk atomCount() through the accessors above, so they are the paths
  // the fuzzer actually crashed in.
  EXPECT_EQ(molecule.centerOfGeometry(), Vector3(0.5, 1.0, 1.5));
  EXPECT_TRUE(std::isfinite(molecule.radius()));
}

TEST_F(MoleculeTest, swapBondIgnoresOutOfRangeIndices)
{
  // See Graph::swapEdgeIndices(): an undo command can hold a bond index that
  // is no longer a bond. m_bondOrders was indexed with it unchecked.
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(1);
  molecule.addBond(0, 1, 1);

  molecule.swapBond(0, 3);
  molecule.swapBond(2, 0);
  molecule.swapAtom(0, 5);
  molecule.swapAtom(8, 1);

  EXPECT_EQ(static_cast<Index>(2), molecule.atomCount());
  EXPECT_EQ(static_cast<Index>(1), molecule.bondCount());
  EXPECT_EQ(1, molecule.bondOrder(0));
  EXPECT_EQ(6, molecule.atom(0).atomicNumber());
}

namespace {

// Every array Molecule keeps that is indexed by atom or by bond, checked
// against atomCount()/bondCount() and against each other. An array that
// setXxx() grows lazily (positions, labels, colors, ...) is allowed to be
// shorter than the count it is keyed by -- see atomWithoutPosition above --
// but never longer, and every stored atom/bond index has to name a real
// atom or bond. SCOPED_TRACE names the mutation under test, so a failure
// says which step broke it.
//
// This checks structure, not content: a ragged (partially populated) array
// can pass every check here while still holding a removed atom's data at
// the index a different atom now occupies, because its size never leaves
// the allowed range either way. See
// RemoveAtomInRaggedOptionalArrayClearsStaleEntry, which needs known content
// to catch that instead. The bond-label bound below is a real guarantee now
// that removeBond()/swapBond() keep m_bondLabels in step (see
// RemoveBondLabelFollowsSwappedInBond) -- makeDecoratedMolecule() exercises
// it on every call below rather than leaving it untested.
//
// The element mask is included here too, now that removeAtom() updates it
// correctly (see RemoveAtomElementMaskDropsExtinctElement); it used to be
// checked separately to avoid tripping that bug on every test that used more
// than one element.
void expectConsistent(const Molecule& mol, const std::string& step)
{
  SCOPED_TRACE(step);
  const Index n = mol.atomCount();
  const Index m = mol.bondCount(); // asserts m_graph/m_bondOrders agree

  EXPECT_EQ(mol.graph().vertexCount(), static_cast<size_t>(n));
  EXPECT_EQ(mol.bondOrders().size(), static_cast<size_t>(m));
  EXPECT_EQ(mol.bondPairs().size(), static_cast<size_t>(m));
  EXPECT_LE(mol.bondLabels().size(), static_cast<size_t>(m));
  EXPECT_EQ(mol.layer().atomCount(), static_cast<size_t>(n));

  Molecule::ElementMask expectedElements;
  for (Index i = 0; i < n; ++i) {
    const unsigned char z = mol.atomicNumber(i);
    expectedElements.set(z < Avogadro::Core::element_count
                           ? z
                           : Avogadro::Core::element_count - 1);
  }
  EXPECT_EQ(expectedElements, mol.elements());

  for (Index i = 0; i < m; ++i) {
    const auto& pair = mol.bondPairs()[i];
    EXPECT_LT(pair.first, n) << "bond " << i << " endpoint a";
    EXPECT_LT(pair.second, n) << "bond " << i << " endpoint b";
  }

  EXPECT_LE(mol.atomPositions2d().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.atomPositions3d().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.atomLabels().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.hybridizations().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.formalCharges().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.isotopes().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.colors().size(), static_cast<size_t>(n));
  EXPECT_LE(mol.forceVectors().size(), static_cast<size_t>(n));

  // Stored as 3 rows per atom; see setFrozenAtom().
  const Eigen::Index maskRows = mol.frozenAtomMask().rows();
  EXPECT_EQ(maskRows % 3, 0);
  EXPECT_LE(maskRows / 3, static_cast<Eigen::Index>(n));

  // Residue-indexed, but the Atom proxies in each name map carry atom
  // indices. swapAtom() reindexes them (SwapAtomReindexesResidues);
  // removeAtom() deliberately does not -- see the comment above
  // swapAtom() in molecule.cpp -- so a reference can silently name the
  // wrong atom after a removal without ever going out of bounds. Bounds
  // is all this checks.
  for (const auto& residue : mol.residues()) {
    for (const auto& atom : residue.residueAtoms())
      EXPECT_LT(atom.index(), n) << "residue atom";
  }

  auto expectAtomReference = [n](Index index, const char* what) {
    if (index != Avogadro::MaxIndex)
      EXPECT_LT(index, n) << what;
  };
  for (const auto& constraint : mol.constraints()) {
    expectAtomReference(constraint.aIndex(), "constraint a");
    expectAtomReference(constraint.bIndex(), "constraint b");
    expectAtomReference(constraint.cIndex(), "constraint c");
    expectAtomReference(constraint.dIndex(), "constraint d");
  }
  for (const auto& coordinate : mol.scanCoordinates()) {
    expectAtomReference(coordinate.aIndex(), "scan a");
    expectAtomReference(coordinate.bIndex(), "scan b");
    expectAtomReference(coordinate.cIndex(), "scan c");
    expectAtomReference(coordinate.dIndex(), "scan d");
  }
}

// A molecule with every optional per-atom array populated, a multi-order
// bond, a residue, a constraint, a selection, a frozen atom, partial
// charges, two coordinate sets and a mesh -- the shape most likely to
// expose an array removeAtom()/swapAtom() forgot. Bond labels are populated
// too, now that removeBond()/swapBond() keep m_bondLabels in step (see
// RemoveBondLabelFollowsSwappedInBond); expectConsistent() checks its bound
// on every use of this fixture rather than the fixture dodging the array.
Molecule makeDecoratedMolecule()
{
  Molecule mol;
  mol.addAtom(6); // 0: C
  mol.addAtom(7); // 1: N
  mol.addAtom(8); // 2: O
  mol.addAtom(1); // 3: H
  mol.addAtom(1); // 4: H

  for (Index i = 0; i < mol.atomCount(); ++i) {
    const auto fi = static_cast<double>(i);
    mol.setAtomPosition3d(i, Vector3(fi, fi * 0.1, 0.0));
    mol.setAtomPosition2d(i, Vector2(fi, 0.0));
    mol.setAtomLabel(i, "atom" + std::to_string(i));
    mol.setFormalCharge(i, static_cast<signed char>(i == 2 ? -1 : 0));
    mol.setIsotope(i, i == 3 ? 2 : 0);
    mol.setHybridization(i, Avogadro::Core::SP3);
    mol.setColor(i,
                 Avogadro::Vector3ub(static_cast<unsigned char>(10 * i), 0, 0));
  }
  mol.setAtomSelected(1, true);
  mol.setAtomSelected(3, true);
  mol.setFrozenAtom(4, true);

  mol.addBond(0, 1, 1);
  mol.addBond(0, 2, 2);
  mol.addBond(1, 3, 1);
  mol.addBond(1, 4, 1);
  for (Index i = 0; i < mol.bondCount(); ++i)
    mol.setBondLabel(i, "bond" + std::to_string(i));

  std::string resName = "LIG";
  Index resNumber = 1;
  char chain = 'A';
  Avogadro::Core::Residue& residue = mol.addResidue(resName, resNumber, chain);
  residue.addResidueAtom("C1", mol.atom(0));

  mol.addConstraint(1.4, 0, 1);

  Array<Vector3> secondSet;
  for (Index i = 0; i < mol.atomCount(); ++i)
    secondSet.push_back(Vector3(static_cast<double>(i) * 2.0, 0.0, 0.0));
  mol.setCoordinate3d(mol.atomPositions3d(), 0);
  mol.setCoordinate3d(secondSet, 1);

  MatrixX charges(static_cast<Eigen::Index>(mol.atomCount()), 1);
  for (Eigen::Index i = 0; i < charges.rows(); ++i)
    charges(i, 0) = 0.1 * static_cast<double>(i);
  mol.setPartialCharges("gasteiger", charges);

  Mesh* mesh = mol.addMesh();
  Array<Vector3f> vertices;
  vertices.push_back(Vector3f(1.0f, 2.0f, 3.0f));
  mesh->setVertices(vertices);

  return mol;
}

} // namespace

TEST_F(MoleculeTest, RemoveAtomFirstFromDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();
  expectConsistent(molecule, "before removeAtom(first)");

  // removeAtom() swaps the last atom (4: H, frozen) into the hole, so slot 0
  // must end up with atom 4's own data, not atom 0's leftovers.
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(0)));
  expectConsistent(molecule, "after removeAtom(first)");

  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(4));
  EXPECT_EQ(1, molecule.atom(0).atomicNumber());
  EXPECT_EQ(molecule.atomLabel(0), "atom4");
  EXPECT_EQ(molecule.atomPosition3d(0), Vector3(4.0, 0.4, 0.0));
  EXPECT_EQ(molecule.color(0), Avogadro::Vector3ub(40, 0, 0));
  EXPECT_EQ(molecule.formalCharge(0), 0);
  EXPECT_TRUE(molecule.frozenAtom(0));
  EXPECT_FALSE(molecule.atomSelected(0));

  // Atoms untouched by the swap-and-pop keep their own data.
  EXPECT_EQ(molecule.atomLabel(1), "atom1");
  EXPECT_TRUE(molecule.atomSelected(1));
}

TEST_F(MoleculeTest, RemoveAtomMiddleFromDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();
  expectConsistent(molecule, "before removeAtom(middle)");

  // Removing atom 2 (O) swaps atom 4 (H, frozen) into slot 2.
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(2)));
  expectConsistent(molecule, "after removeAtom(middle)");

  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(4));
  EXPECT_EQ(1, molecule.atom(2).atomicNumber());
  EXPECT_EQ(molecule.atomLabel(2), "atom4");
  EXPECT_EQ(molecule.atomPosition3d(2), Vector3(4.0, 0.4, 0.0));
  EXPECT_TRUE(molecule.frozenAtom(2));
  EXPECT_FALSE(molecule.atomSelected(2));

  EXPECT_EQ(molecule.atomLabel(0), "atom0");
  EXPECT_EQ(molecule.atomLabel(1), "atom1");
  EXPECT_TRUE(molecule.atomSelected(1));
}

TEST_F(MoleculeTest, RemoveAtomLastFromDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();
  expectConsistent(molecule, "before removeAtom(last)");

  // Atom 4 is already last, so removeAtom() is a plain pop: nothing is
  // swapped in, and every surviving atom keeps its own index and data.
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(4)));
  expectConsistent(molecule, "after removeAtom(last)");

  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(4));
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    EXPECT_EQ(molecule.atomLabel(i), "atom" + std::to_string(i))
      << "atom " << i;
  }
  EXPECT_TRUE(molecule.atomSelected(1));
  EXPECT_TRUE(molecule.atomSelected(3));
}

TEST_F(MoleculeTest, RemoveOnlyAtomStaysConsistent)
{
  Molecule molecule;
  molecule.addAtom(8);
  molecule.setAtomLabel(0, "lone");
  molecule.setAtomSelected(0, true);
  molecule.setFrozenAtom(0, true);
  ASSERT_TRUE(molecule.elements().test(8));

  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(0)));
  expectConsistent(molecule, "after removing the only atom");

  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(0));
  // With no other atom to loop over, removeAtom()'s element-mask update
  // takes this path trivially -- see RemoveAtomElementMaskKeepsSurvivingElement
  // and RemoveAtomElementMaskDropsExtinctElement for the cases that
  // distinguish "another atom of the same element" from "any other atom".
  EXPECT_FALSE(molecule.elements().test(8));
}

TEST_F(MoleculeTest, SwapAtomOnDecoratedMoleculeCarriesEveryArray)
{
  Molecule molecule = makeDecoratedMolecule();
  expectConsistent(molecule, "before swapAtom");

  molecule.swapAtom(0, 4);
  expectConsistent(molecule, "after swapAtom");

  // Atom 0's data (C, unselected, unfrozen) is now at index 4.
  EXPECT_EQ(6, molecule.atom(4).atomicNumber());
  EXPECT_EQ(molecule.atomLabel(4), "atom0");
  EXPECT_EQ(molecule.atomPosition3d(4), Vector3(0.0, 0.0, 0.0));
  EXPECT_EQ(molecule.atomPosition2d(4), Vector2(0.0, 0.0));
  EXPECT_EQ(molecule.color(4), Avogadro::Vector3ub(0, 0, 0));
  EXPECT_FALSE(molecule.atomSelected(4));
  EXPECT_FALSE(molecule.frozenAtom(4));

  // Atom 4's data (H, frozen) is now at index 0.
  EXPECT_EQ(1, molecule.atom(0).atomicNumber());
  EXPECT_EQ(molecule.atomLabel(0), "atom4");
  EXPECT_EQ(molecule.atomPosition3d(0), Vector3(4.0, 0.4, 0.0));
  EXPECT_TRUE(molecule.frozenAtom(0));
  EXPECT_FALSE(molecule.atomSelected(0));

  // Atom count and bond count are unchanged by a relabelling.
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(5));
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(4));
}

TEST_F(MoleculeTest, SwapAtomSameIndexIsANoOp)
{
  Molecule before = makeDecoratedMolecule();
  Molecule after = before;

  after.swapAtom(2, 2);
  expectConsistent(after, "after swapAtom(i, i)");

  ASSERT_EQ(before.atomCount(), after.atomCount());
  for (Index i = 0; i < before.atomCount(); ++i) {
    EXPECT_EQ(before.atomLabel(i), after.atomLabel(i)) << "atom " << i;
    EXPECT_EQ(before.atomPosition3d(i), after.atomPosition3d(i))
      << "atom " << i;
    EXPECT_EQ(before.frozenAtom(i), after.frozenAtom(i)) << "atom " << i;
    EXPECT_EQ(before.atomSelected(i), after.atomSelected(i)) << "atom " << i;
  }
}

TEST_F(MoleculeTest, RemoveBondFromDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();
  expectConsistent(molecule, "before removeBond");
  ASSERT_EQ(molecule.bondCount(), static_cast<Index>(4));

  ASSERT_TRUE(molecule.removeBond(static_cast<Index>(0)));
  expectConsistent(molecule, "after removeBond");
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(3));

  // A structural edit invalidates calculated results.
  EXPECT_TRUE(molecule.partialCharges("gasteiger").isZero());

  // Atom-level decoration is untouched by removing a bond.
  EXPECT_EQ(molecule.atomLabel(0), "atom0");
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(5));
}

TEST_F(MoleculeTest, ClearBondsOnDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();

  molecule.clearBonds();
  expectConsistent(molecule, "after clearBonds");

  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(0));
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(5));
  // clearBonds() is "re-perceive connectivity", not a structural edit to the
  // atoms -- see the comment on it in molecule.cpp -- so atom decoration
  // survives it.
  EXPECT_EQ(molecule.atomLabel(0), "atom0");
  EXPECT_TRUE(molecule.atomSelected(1));
}

TEST_F(MoleculeTest, ClearAtomsOnDecoratedMoleculeStaysConsistent)
{
  Molecule molecule = makeDecoratedMolecule();

  molecule.clearAtoms();
  expectConsistent(molecule, "after clearAtoms");

  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(0));
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(0));
  EXPECT_EQ(molecule.residueCount(), static_cast<Index>(0));
  EXPECT_TRUE(molecule.constraints().empty());
  EXPECT_TRUE(molecule.scanCoordinates().empty());
}

TEST_F(MoleculeTest, AddAtomAfterRemovalGetsDefaultsNotStaleData)
{
  Molecule molecule = makeDecoratedMolecule();
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(2)));
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(0)));

  Atom fresh = molecule.addAtom(6);
  expectConsistent(molecule, "after addAtom following removals");

  // The new atom's optional-array entries read as defaults, not whatever a
  // removed atom happened to leave in that slot. Position and force are
  // covered separately, by AtomPositionAndForceDefaultToZero: their default
  // is Vector::Zero(), not whatever an uninitialized Eigen vector holds.
  EXPECT_EQ(molecule.atomLabel(fresh.index()), "");
  EXPECT_EQ(molecule.formalCharge(fresh.index()), 0);
  EXPECT_EQ(molecule.isotope(fresh.index()), static_cast<unsigned short>(0));
  EXPECT_FALSE(molecule.atomSelected(fresh.index()));
  EXPECT_FALSE(molecule.frozenAtom(fresh.index()));
  EXPECT_EQ(molecule.color(fresh.index()),
            Avogadro::Vector3ub(Avogadro::Core::Elements::color(6)));
}

TEST_F(MoleculeTest, RemoveAtomElementMaskKeepsSurvivingElement)
{
  // The counterpart to RemoveAtomElementMaskDropsExtinctElement: with a
  // second oxygen still present, the mask is right either way, so this one
  // was never disabled.
  Molecule molecule;
  Atom o1 = molecule.addAtom(8);
  molecule.addAtom(8);
  expectConsistent(molecule, "before removing one of two oxygens");

  ASSERT_TRUE(molecule.removeAtom(o1));
  expectConsistent(molecule, "after removing one of two oxygens");
  EXPECT_TRUE(molecule.elements().test(8));
}

TEST_F(MoleculeTest, RandomMixedMutationsStayConsistent)
{
  // ~500 mixed structural and per-atom-state mutations, checked after every
  // one. This is the pattern the 2.1 bug hunt is aimed at: a parallel array
  // drifting out of step with atomCount()/bondCount() after some mutation,
  // then getting indexed later. Op 8 (setBondLabel) also exercises the
  // ragged case: labelling a bond and then adding atoms/bonds afterwards
  // (ops 0/1, already in the mix) leaves m_bondLabels short of bondCount(),
  // the state RemoveBondLabelFollowsSwappedInBond covers with known
  // content. Fixed seed for reproducibility.
  Molecule molecule;
  std::mt19937 rng(20260922u);
  std::uniform_int_distribution<int> opPicker(0, 8);
  std::uniform_int_distribution<int> elementPicker(1, 10);
  std::uniform_int_distribution<int> boolPicker(0, 1);

  for (int step = 0; step < 500; ++step) {
    const Index n = molecule.atomCount();
    const int op = (n == 0) ? 0 : opPicker(rng);
    std::uniform_int_distribution<Index> pickAtom(0, n == 0 ? 0 : n - 1);

    switch (op) {
      case 0:
        molecule.addAtom(static_cast<unsigned char>(elementPicker(rng)));
        break;
      case 1: {
        if (n >= 2) {
          const Index a = pickAtom(rng);
          const Index b = pickAtom(rng);
          if (a != b)
            molecule.addBond(a, b, 1);
        }
        break;
      }
      case 2:
        molecule.removeAtom(pickAtom(rng));
        break;
      case 3: {
        const Index bc = molecule.bondCount();
        if (bc > 0) {
          std::uniform_int_distribution<Index> pickBond(0, bc - 1);
          molecule.removeBond(pickBond(rng));
        }
        break;
      }
      case 4:
        molecule.swapAtom(pickAtom(rng), pickAtom(rng));
        break;
      case 5:
        molecule.setAtomSelected(pickAtom(rng), boolPicker(rng) != 0);
        break;
      case 6:
        molecule.setFrozenAtom(pickAtom(rng), boolPicker(rng) != 0);
        break;
      case 7:
        molecule.setAtomLabel(pickAtom(rng), "step" + std::to_string(step));
        break;
      case 8: {
        const Index bc = molecule.bondCount();
        if (bc > 0) {
          std::uniform_int_distribution<Index> pickBond(0, bc - 1);
          molecule.setBondLabel(pickBond(rng), "step" + std::to_string(step));
        }
        break;
      }
      default:
        break;
    }

    expectConsistent(molecule, "random step " + std::to_string(step) + " (op " +
                                 std::to_string(op) + ")");
  }
}

// Invariant: the "is there another atom of this element" scan in
// removeAtom() must compare each remaining atom's element against the one
// being removed, not the removed element against itself -- so the mask
// drops an element once its last atom is gone, even with other atoms (of
// other elements) still present.
TEST_F(MoleculeTest, RemoveAtomElementMaskDropsExtinctElement)
{
  Molecule molecule;
  molecule.addAtom(6);               // C, stays
  Atom oxygen = molecule.addAtom(8); // the molecule's only O
  ASSERT_TRUE(molecule.elements().test(8));

  ASSERT_TRUE(molecule.removeAtom(oxygen));

  EXPECT_FALSE(molecule.elements().test(8));
}

// Invariant: a custom element's atomic number (CustomElementMin..Max, well
// above element_count) is folded onto bit element_count - 1 -- the same
// clamp addAtom()/setAtomicNumber() apply, see the comment in addAtom() --
// so removeAtom()'s element-mask scan has to compare and reset that folded
// bit, not the raw atomic number. Comparing/resetting the raw number would
// call std::bitset::reset() with an out-of-range bit and throw.
TEST_F(MoleculeTest, RemoveAtomElementMaskClampsCustomElement)
{
  Molecule molecule;
  molecule.addAtom(6); // C, stays
  Atom custom = molecule.addAtom(Avogadro::CustomElementMin);
  ASSERT_TRUE(molecule.elements().test(6));
  ASSERT_TRUE(molecule.elements().test(Avogadro::Core::element_count - 1));

  ASSERT_TRUE(molecule.removeAtom(custom)); // must not throw

  EXPECT_TRUE(molecule.elements().test(6));
  EXPECT_FALSE(molecule.elements().test(Avogadro::Core::element_count - 1));
}

// Invariant: the counterpart to the extinct-element case above, for custom
// elements. Two different custom atomic numbers fold onto the same bit, so
// removing the atom that holds one of them must not clear that bit while a
// different custom element is still present -- which raw-number comparison
// would get wrong, since the two numbers are never equal.
TEST_F(MoleculeTest, RemoveAtomElementMaskKeepsSharedBitForOtherCustomElement)
{
  Molecule molecule;
  Atom first = molecule.addAtom(Avogadro::CustomElementMin);
  molecule.addAtom(static_cast<unsigned char>(Avogadro::CustomElementMin + 1));
  ASSERT_TRUE(molecule.elements().test(Avogadro::Core::element_count - 1));

  ASSERT_TRUE(molecule.removeAtom(first));

  EXPECT_TRUE(molecule.elements().test(Avogadro::Core::element_count - 1));
}

// Invariant: setAtomicNumbers() rebuilds the element mask whether or not
// per-atom colours are set (it used to rebuild it only alongside the
// colours, leaving it empty otherwise), and folds custom elements onto bit
// element_count - 1 like addAtom() -- the raw number would throw.
TEST_F(MoleculeTest, SetAtomicNumbersRebuildsElementMask)
{
  Molecule molecule;
  molecule.addAtom(1);
  molecule.addAtom(1);
  ASSERT_TRUE(molecule.colors().empty());

  Array<unsigned char> numbers;
  numbers.push_back(6);
  numbers.push_back(Avogadro::CustomElementMin);
  ASSERT_TRUE(molecule.setAtomicNumbers(numbers)); // must not throw

  EXPECT_FALSE(molecule.elements().test(1));
  EXPECT_TRUE(molecule.elements().test(6));
  EXPECT_TRUE(molecule.elements().test(Avogadro::Core::element_count - 1));
}

// Invariant: removeBond()'s swap-and-pop must carry m_bondLabels along with
// every other per-bond array (m_bondOrders, m_bondProperties, the graph
// edges), so a label follows the bond it was set on rather than staying
// behind at the bond's old index.
TEST_F(MoleculeTest, RemoveBondLabelFollowsSwappedInBond)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addBond(0, 1, 1); // bond 0
  molecule.addBond(1, 2, 1); // bond 1
  molecule.setBondLabel(1, "target");

  // removeBond(0) swaps bond 1 into slot 0 (swap-and-pop), so the label
  // should follow it there.
  ASSERT_TRUE(molecule.removeBond(static_cast<Index>(0)));
  ASSERT_EQ(molecule.bondCount(), static_cast<Index>(1));

  EXPECT_EQ(molecule.bondLabel(0), "target");
}

// Invariant: an optional per-atom array shorter than atomCount() (because an
// atom was added after the array was last set) must still behave correctly
// under swap-and-pop removal -- the atom that moves into the removed slot
// has no entry of its own, so that slot has to read back as the default,
// never as the removed atom's stale value.
TEST_F(MoleculeTest, RemoveAtomInRaggedOptionalArrayClearsStaleEntry)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setAtomLabel(0, "zero");
  molecule.setAtomLabel(1, "one");
  molecule.setAtomLabel(2, "two"); // m_atomLabels is now exactly atomCount().

  // Added after the labels were set, so it has none: m_atomLabels stays at
  // 3 while atomCount() becomes 4.
  molecule.addAtom(6);

  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(1)));
  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(3));

  // Atom 3 (never labelled) swapped into slot 1; the stale "one" must be
  // gone, not left behind from the atom that used to be there.
  EXPECT_EQ(molecule.atomLabel(1), "");
}

// Invariant: the "reset a stale entry" and "grow to cover a new atom" cases
// above must fill with a real value, not a default-constructed T(). For an
// Eigen fixed-size type like Vector3, T() is left uninitialized rather than
// zeroed, so m_positions3d and friends used to pick up garbage instead of
// Vector3::Zero(). m_colors has no zero-like default at all -- it has to
// fall back to the atom's own element colour, the same fallback
// Molecule::color() uses for an atom past the end of m_colors (see color()
// in molecule.h).
TEST_F(MoleculeTest, RemoveAtomInRaggedOptionalArrayResetsWithRealValues)
{
  Molecule molecule;
  molecule.addAtom(6); // 0: C, stays
  molecule.addAtom(7); // 1: N, removed
  molecule.addAtom(8); // 2: O, positioned/coloured
  molecule.addAtom(1); // 3: H, the last atom -- never positioned/coloured

  molecule.setAtomPosition3d(0, Vector3(1.0, 1.0, 1.0));
  molecule.setAtomPosition3d(1, Vector3(2.0, 2.0, 2.0));
  molecule.setAtomPosition3d(2, Vector3(3.0, 3.0, 3.0));
  molecule.setColor(0, Avogadro::Vector3ub(10, 10, 10));
  molecule.setColor(1, Avogadro::Vector3ub(20, 20, 20));
  molecule.setColor(2, Avogadro::Vector3ub(30, 30, 30));
  // m_positions3d/m_colors now cover atoms 0-2 (3 entries); atom 3 (H) has
  // none, so atomCount() (4) is one ahead of them.

  // removeAtom(1) swaps the last atom (3, H, uncovered) into slot 1.
  ASSERT_TRUE(molecule.removeAtom(static_cast<Index>(1)));
  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(3));

  EXPECT_EQ(molecule.atomPositions3d()[1], Vector3::Zero());
  EXPECT_EQ(molecule.colors()[1],
            Avogadro::Vector3ub(Avogadro::Core::Elements::color(1))); // H
}

// Invariant: the counterpart to the removal case above, for swapAtom(). One
// side of the swap has a label and the other (added afterwards) does not, so
// the short array has to grow enough for the label to travel to its atom's
// new index instead of being silently dropped because the array never
// reached that far.
TEST_F(MoleculeTest, SwapAtomInRaggedOptionalArrayMovesLabelToNewIndex)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setAtomLabel(0, "zero");
  molecule.setAtomLabel(1, "one"); // m_atomLabels is now exactly atomCount().

  // Added after the labels were set: m_atomLabels stays at 2 while
  // atomCount() becomes 3.
  molecule.addAtom(6);

  molecule.swapAtom(1, 2);

  // Atom 1's label travels to index 2 ...
  EXPECT_EQ(molecule.atomLabel(2), "one");
  // ... and the atom swapped into index 1 (never labelled) reads back
  // unlabelled, not still showing "one".
  EXPECT_EQ(molecule.atomLabel(1), "");
}

// Invariant: the counterpart to
// RemoveAtomInRaggedOptionalArrayResetsWithRealValues, for the growth case in
// swapAtom(): every newly-covered index -- not just the one the swap lands
// on -- has to be filled with a real value rather than an uninitialized
// Eigen vector or a meaningless "no colour".
TEST_F(MoleculeTest, SwapAtomInRaggedOptionalArrayFillsGrowthWithRealValues)
{
  Molecule molecule;
  molecule.addAtom(6); // 0: C, positioned/coloured below
  molecule.addAtom(7); // 1: N, positioned/coloured below
  molecule.addAtom(8); // 2: O, never positioned/coloured
  molecule.addAtom(1); // 3: H, never positioned/coloured

  molecule.setAtomPosition3d(0, Vector3(1.0, 2.0, 3.0));
  molecule.setAtomPosition3d(1, Vector3(4.0, 5.0, 6.0));
  molecule.setColor(0, Avogadro::Vector3ub(10, 20, 30));
  molecule.setColor(1, Avogadro::Vector3ub(40, 50, 60));
  // m_positions3d/m_colors are now exactly 2 long; atoms 2 and 3 have none.

  // Swap atom 1 (covered) with atom 3 (not covered): grows the arrays to
  // cover index 3, filling the newly-covered index 2 along the way -- a tail
  // atom that is not itself part of the swap.
  molecule.swapAtom(1, 3);

  // Index 2 (O, untouched by the swap) reads back as the real defaults.
  EXPECT_EQ(molecule.atomPositions3d()[2], Vector3::Zero());
  EXPECT_EQ(molecule.colors()[2],
            Avogadro::Vector3ub(Avogadro::Core::Elements::color(8))); // O

  // Atom 3 (H, also never covered) swapped into index 1, and reads back the
  // same way.
  EXPECT_EQ(molecule.atomPositions3d()[1], Vector3::Zero());
  EXPECT_EQ(molecule.colors()[1],
            Avogadro::Vector3ub(Avogadro::Core::Elements::color(1))); // H

  // Atom 1's own data (N) travelled to index 3.
  EXPECT_EQ(molecule.atomPositions3d()[3], Vector3(4.0, 5.0, 6.0));
  EXPECT_EQ(molecule.colors()[3], Avogadro::Vector3ub(40, 50, 60));
}

// Invariant: the same growth rule applies to m_frozenAtomMask, which is
// stored as 3 doubles per atom rather than as an Array<T>.
TEST_F(MoleculeTest, SwapAtomInRaggedFrozenMaskMovesFrozenStateToNewIndex)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setFrozenAtom(0, true);
  molecule.setFrozenAtom(1, true); // m_frozenAtomMask now covers both atoms.

  // Added after the mask was set: it stays sized for 2 atoms while
  // atomCount() becomes 3.
  molecule.addAtom(6);
  ASSERT_FALSE(molecule.frozenAtom(2));

  molecule.swapAtom(1, 2);

  // Atom 1's frozen state travels to index 2 ...
  EXPECT_TRUE(molecule.frozenAtom(2));
  // ... and the atom swapped into index 1 (never frozen) reads back
  // unfrozen.
  EXPECT_FALSE(molecule.frozenAtom(1));
}

// Invariant: selection follows the same ragged-array rules. An atom added
// after the last setAtomSelected() has no entry, so it reads unselected
// wherever a swap or removal moves it.
TEST_F(MoleculeTest, SwapAndRemoveAtomInRaggedSelection)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(6);
  molecule.setAtomSelected(1, true); // m_selectedAtoms is now 2 long.
  molecule.addAtom(6);
  molecule.addAtom(6);

  molecule.swapAtom(1, 3);
  EXPECT_FALSE(molecule.atomSelected(1));
  EXPECT_TRUE(molecule.atomSelected(3));

  molecule.swapAtom(1, 3); // Back to atom 1, with the array now full length.
  molecule.addAtom(6);     // Short again: 4 entries, 5 atoms.
  molecule.removeAtom(1);  // Unselected atom 4 moves into slot 1.
  EXPECT_FALSE(molecule.atomSelected(1));
  EXPECT_TRUE(molecule.isSelectionEmpty());
}

// boundingBox() used to index the selection for every atom, reading past the
// end for atoms added after the last selection change.
TEST_F(MoleculeTest, BoundingBoxWithRaggedSelectionUsesOnlySelectedAtoms)
{
  Molecule molecule;
  molecule.addAtom(6).setPosition3d(Vector3(0.0, 0.0, 0.0));
  molecule.addAtom(6).setPosition3d(Vector3(1.0, 0.0, 0.0));
  molecule.setAtomSelected(0, true);
  molecule.addAtom(6).setPosition3d(Vector3(10.0, 0.0, 0.0));

  Vector3 boxMin, boxMax;
  molecule.boundingBox(boxMin, boxMax, 0.5);
  EXPECT_DOUBLE_EQ(boxMin.x(), -0.5);
  EXPECT_DOUBLE_EQ(boxMax.x(), 0.5);
}

// Invariant: Molecule::atomPosition2d(), Molecule::atomPosition3d() and
// Molecule::forceVector() must return Vector2::Zero() / Vector3::Zero() for
// an atom with no position or force set, as their doc comments in molecule.h
// promise -- not a default-constructed Vector2()/Vector3(), whose fixed-size
// Eigen coefficients are left uninitialized rather than zeroed.
TEST_F(MoleculeTest, AtomPositionAndForceDefaultToZero)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.setAtomPosition3d(0, Vector3(1.0, 2.0, 3.0));
  molecule.setAtomPosition2d(0, Vector2(1.0, 2.0));
  Array<Vector3> forces;
  forces.push_back(Vector3(0.5, 0.5, 0.5));
  ASSERT_TRUE(molecule.setForceVectors(forces));

  // Every optional array is now exactly as long as the molecule; appending
  // an atom leaves them one short, the same ragged state atomWithoutPosition
  // exercises above -- but read here through Molecule's own getters rather
  // than the Atom proxy, which does not have this bug.
  molecule.addAtom(1);

  EXPECT_EQ(molecule.atomPosition3d(1), Vector3::Zero());
  EXPECT_EQ(molecule.atomPosition2d(1), Vector2::Zero());
  EXPECT_EQ(molecule.forceVector(1), Vector3::Zero());
}

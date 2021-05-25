/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/array.h>
#include <avogadro/core/color3f.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/persistentatom.h>
#include <avogadro/qtgui/persistentbond.h>

#include "utils.h"

using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::PersistentAtom;
using Avogadro::QtGui::PersistentBond;
using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::Bond;
using Avogadro::Core::Color3f;
using Avogadro::Core::Mesh;
using Avogadro::Index;

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
  Bond b[2];
  b[0] = m_testMolecule.addBond(o1, h2, 1);
  b[1] = m_testMolecule.addBond(o1, h3, 2);

  o1.setPosition3d(Avogadro::Vector3(0, 0, 0));
  h2.setPosition3d(Avogadro::Vector3(0.6, -0.5, 0));
  h3.setPosition3d(Avogadro::Vector3(-0.6, -0.5, 0));

  o1.setPosition2d(Avogadro::Vector2(0, 0));
  h2.setPosition2d(Avogadro::Vector2(0.6, -0.5));
  h3.setPosition2d(Avogadro::Vector2(-0.6, -0.5));

  // Add some data
  Avogadro::Core::VariantMap data;
  data.setValue("test", Avogadro::Core::Variant("test"));
  m_testMolecule.setDataMap(data);

  Mesh* mesh = m_testMolecule.addMesh();

  Array<Avogadro::Vector3f> vertices;
  Array<Avogadro::Vector3f> normals;
  Array<Color3f> colors;

  Color3f color = Color3f(23, 23, 23);
  colors.push_back(color);

  Avogadro::Vector3f vec(1.2f, 1.3f, 1.4f);

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

  Atom atom = molecule.addAtom(6);
  EXPECT_EQ(atom.isValid(), true);
  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(1));
  EXPECT_EQ(atom.index(), 0);
  EXPECT_EQ(atom.atomicNumber(), static_cast<unsigned char>(6));

  Atom atom2 = molecule.addAtom(1);
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

  // try to lookup nonexistant bond
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

TEST_F(MoleculeTest, uniqueAtom)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  Bond b1 = molecule.addBond(a1, a2, 1);
  Bond b2 = molecule.addBond(a1, a3, 2);

  Index uid1 = molecule.atomUniqueId(a1);
  Index uid2 = molecule.atomUniqueId(a2);
  Index uid3 = molecule.atomUniqueId(a3);
  EXPECT_EQ(uid1, 0);
  EXPECT_EQ(uid2, 1);
  EXPECT_EQ(uid3, 2);

  EXPECT_EQ(molecule.bond(a1, a2).index(), b1.index());
  EXPECT_EQ(molecule.bond(a2, a1).index(), b1.index());
  EXPECT_EQ(molecule.bond(a3, a1).index(), b2.index());

  Array<Bond> bonds = molecule.bonds(a1);
  EXPECT_EQ(bonds.size(), 2);

  molecule.removeAtom(a2);
  bonds = molecule.bonds(a1);
  EXPECT_EQ(bonds.size(), 1);

  Atom a4 = molecule.addAtom(8);
  Index uid4 = molecule.atomUniqueId(a4);
  EXPECT_EQ(uid4, 3);
  molecule.addBond(a1, a4, 1);
  EXPECT_EQ(molecule.bonds(a1).size(), 2);
  EXPECT_EQ(molecule.bonds(a3).size(), 1);

  // Check we can get the invalid atom, and also resolve the unique IDs to the
  // correct atom objects.
  Atom test = molecule.atomByUniqueId(uid1);
  EXPECT_TRUE(a1 == test);
  test = molecule.atomByUniqueId(uid2);
  EXPECT_FALSE(test.isValid());
  test = molecule.atomByUniqueId(uid4);
  EXPECT_FALSE(a1 == test);
  EXPECT_TRUE(a4 == test);
  EXPECT_TRUE(a2 != test);
  EXPECT_EQ(test.atomicNumber(), 8);
}

TEST_F(MoleculeTest, uniqueAtomRestore)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  molecule.addBond(a1, a2, 1);
  molecule.addBond(a1, a3, 2);

  Index uid1 = molecule.atomUniqueId(a1);
  Index uid2 = molecule.atomUniqueId(a2);

  molecule.removeAtom(a2);

  Atom a4 = molecule.addAtom(8);
  molecule.addBond(a1, a4, 1);

  // Check we can get the invalid atom, and also resolve the unique IDs to the
  // correct atom objects.
  Atom test = molecule.atomByUniqueId(uid1);
  EXPECT_TRUE(a1 == test);
  test = molecule.atomByUniqueId(uid2);
  EXPECT_FALSE(test.isValid());
  test = molecule.addAtom(8, uid2);
  EXPECT_TRUE(test.isValid());
  EXPECT_TRUE(molecule.atomByUniqueId(uid2).isValid());
}

TEST_F(MoleculeTest, persistentAtom)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  molecule.addBond(a1, a2, 1);
  molecule.addBond(a1, a3, 2);

  Molecule::PersistentAtomType pa1(a1);
  Molecule::PersistentAtomType pa2(&molecule, molecule.atomUniqueId(a2));
  Molecule::PersistentAtomType pa3(&molecule, molecule.atomUniqueId(a3));
  EXPECT_EQ(pa1.uniqueIdentifier(), 0);
  EXPECT_EQ(pa2.uniqueIdentifier(), 1);
  EXPECT_EQ(pa3.uniqueIdentifier(), 2);

  molecule.removeAtom(a2);

  Atom a4 = molecule.addAtom(8);
  Molecule::PersistentAtomType pa4(&molecule, molecule.atomUniqueId(a4));
  EXPECT_EQ(pa4.uniqueIdentifier(), 3);
  molecule.addBond(a1, a4, 1);

  // Check we can get the invalid atom, and also resolve the unique IDs to the
  // correct atom objects from their persistent atom containers.
  Atom test = pa1.atom();
  EXPECT_TRUE(a1 == test);
  test = pa2.atom();
  EXPECT_FALSE(pa2.isValid());
  EXPECT_FALSE(test.isValid());
  test = pa4.atom();
  EXPECT_FALSE(a1 == test);
  EXPECT_TRUE(a4 == test);
  EXPECT_TRUE(a2 != test);
  EXPECT_EQ(test.atomicNumber(), 8);
}

TEST_F(MoleculeTest, persistentAtomRestore)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  molecule.addBond(a1, a2, 1);
  molecule.addBond(a1, a3, 2);

  Molecule::PersistentAtomType pa1(a1);
  Molecule::PersistentAtomType pa2(&molecule, molecule.atomUniqueId(a2));

  molecule.removeAtom(pa2.atom());

  Atom a4 = molecule.addAtom(8);
  molecule.addBond(a1, a4, 1);

  // Check we can get the invalid atom, and also resolve the unique IDs to the
  // correct atom objects from their persistent atom containers.
  Atom test = pa1.atom();
  EXPECT_TRUE(a1 == test);
  test = pa2.atom();
  EXPECT_FALSE(test.isValid());
  test = molecule.addAtom(8, pa2.uniqueIdentifier());
  EXPECT_TRUE(test.isValid());
  EXPECT_TRUE(pa2.isValid());
}

TEST_F(MoleculeTest, uniqueBond)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  Atom a4 = molecule.addAtom(8);
  Bond b[5];
  b[0] = molecule.addBond(a1, a2, 1);
  b[1] = molecule.addBond(a1, a3, 2);
  b[2] = molecule.addBond(a1, a4, 3);
  b[3] = molecule.addBond(a4, a3, 2);
  b[4] = molecule.addBond(a2, a3, 1);

  Index uid[5];
  for (int i = 0; i < 5; ++i)
    uid[i] = molecule.bondUniqueId(b[i]);
  EXPECT_EQ(molecule.bondByUniqueId(uid[0]).order(), 1);
  EXPECT_EQ(molecule.bondByUniqueId(uid[1]).order(), 2);
  EXPECT_EQ(molecule.bondByUniqueId(uid[2]).order(), 3);
  EXPECT_EQ(molecule.bondByUniqueId(uid[3]).order(), 2);
  EXPECT_EQ(molecule.bondByUniqueId(uid[4]).order(), 1);
  molecule.removeBond(b[2]);
  EXPECT_EQ(molecule.bondByUniqueId(uid[0]).order(), 1);
  EXPECT_EQ(molecule.bondByUniqueId(uid[1]).order(), 2);
  EXPECT_TRUE(molecule.bondByUniqueId(uid[4]).isValid());
  EXPECT_FALSE(molecule.bondByUniqueId(uid[2]).isValid());
  EXPECT_EQ(molecule.bondByUniqueId(uid[3]).order(), 2);
  EXPECT_EQ(molecule.bondByUniqueId(uid[4]).order(), 1);
  EXPECT_EQ(molecule.bondByUniqueId(uid[3]), b[3]);
}

TEST_F(MoleculeTest, uniqueBondRestore)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  Atom a4 = molecule.addAtom(8);
  Bond b[5];
  b[0] = molecule.addBond(a1, a2, 1);
  b[1] = molecule.addBond(a1, a3, 2);
  b[2] = molecule.addBond(a1, a4, 3);
  b[3] = molecule.addBond(a4, a3, 2);
  b[4] = molecule.addBond(a2, a3, 1);

  Index uid[5];
  for (int i = 0; i < 5; ++i)
    uid[i] = molecule.bondUniqueId(b[i]);
  molecule.removeBond(b[2]);
  EXPECT_EQ(molecule.bondByUniqueId(uid[0]).order(), 1);
  EXPECT_EQ(molecule.bondByUniqueId(uid[1]).order(), 2);
  EXPECT_TRUE(molecule.bondByUniqueId(uid[4]).isValid());
  EXPECT_FALSE(molecule.bondByUniqueId(uid[2]).isValid());
  EXPECT_EQ(molecule.bondByUniqueId(uid[3]).order(), 2);
  EXPECT_EQ(molecule.bondByUniqueId(uid[4]).order(), 1);
  EXPECT_EQ(molecule.bondByUniqueId(uid[3]), b[3]);
  molecule.addBond(a1, a4, 3, uid[2]);
  EXPECT_TRUE(molecule.bondByUniqueId(uid[2]).isValid());
  EXPECT_EQ(molecule.bondByUniqueId(uid[2]).order(), 3);
}

TEST_F(MoleculeTest, atomCount)
{
  Molecule mol;
  mol.addAtom(8);
  mol.addAtom(1);
  mol.addAtom(1);
  // Check the total count, and the counts of specific elements.
  EXPECT_EQ(mol.atomCount(), 3);
  EXPECT_EQ(mol.atomCount(1), 2);
  EXPECT_EQ(mol.atomCount(8), 1);
  EXPECT_EQ(mol.atomCount(42), 0);
}

TEST_F(MoleculeTest, mass)
{
  Molecule mol;
  EXPECT_DOUBLE_EQ(mol.mass(), 0.0);
  Atom a = mol.addAtom(8);
  mol.addAtom(1);
  mol.addAtom(1);
  EXPECT_DOUBLE_EQ(mol.mass(), 18.01508);
  a.setAtomicNumber(9);
  EXPECT_DOUBLE_EQ(mol.mass(), 21.01408);
}

TEST_F(MoleculeTest, centerOfGeometry)
{
  Molecule mol;
  Avogadro::Vector3 center = mol.centerOfGeometry();

  Atom a8 = mol.addAtom(8);
  mol.setAtomPosition3d(a8.index(), Avogadro::Vector3(0.0, 0.0, 0.0));
  center = mol.centerOfGeometry();
  EXPECT_DOUBLE_EQ(center.x(), 0.0);
  EXPECT_DOUBLE_EQ(center.y(), 0.0);
  EXPECT_DOUBLE_EQ(center.z(), 0.0);

  Atom a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(1.0, 0.0, 0.0));
  center = mol.centerOfGeometry();
  EXPECT_DOUBLE_EQ(center.x(), 0.5);
  EXPECT_DOUBLE_EQ(center.y(), 0.0);
  EXPECT_DOUBLE_EQ(center.z(), 0.0);

  a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(0.0, 1.0, -1.0));
  center = mol.centerOfGeometry();
  EXPECT_DOUBLE_EQ(center.x(), 1./3.);
  EXPECT_DOUBLE_EQ(center.y(), 1./3.);
  EXPECT_DOUBLE_EQ(center.z(), -1./3.);

  a8.setAtomicNumber(9);
  center = mol.centerOfGeometry();
  EXPECT_DOUBLE_EQ(center.x(), 1./3.);
  EXPECT_DOUBLE_EQ(center.y(), 1./3.);
  EXPECT_DOUBLE_EQ(center.z(), -1./3.);
}

TEST_F(MoleculeTest, centerOfMass)
{
  Molecule mol;
  Avogadro::Vector3 center = mol.centerOfMass();

  Atom a8 = mol.addAtom(8);
  mol.setAtomPosition3d(a8.index(), Avogadro::Vector3(0.0, 0.0, 0.0));
  center = mol.centerOfMass();
  EXPECT_DOUBLE_EQ(center.x(), 0.0);
  EXPECT_DOUBLE_EQ(center.y(), 0.0);
  EXPECT_DOUBLE_EQ(center.z(), 0.0);

  Atom a = mol.addAtom(2);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(2.0, 0.0, 0.0));
  center = mol.centerOfMass();
  EXPECT_DOUBLE_EQ(center.x(), (2.0 * Avogadro::Core::Elements::mass(2) / mol.atomCount()) / mol.mass());
  EXPECT_DOUBLE_EQ(center.y(), 0.0);
  EXPECT_DOUBLE_EQ(center.z(), 0.0);

  a = mol.addAtom(3);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(1.0, 3.0, -4.0));
  center = mol.centerOfMass();
  EXPECT_DOUBLE_EQ(center.x(), ((2.0 * Avogadro::Core::Elements::mass(2) + 1.0 * Avogadro::Core::Elements::mass(3)) / mol.atomCount()) / mol.mass());
  EXPECT_DOUBLE_EQ(center.y(), (3.0 * Avogadro::Core::Elements::mass(3) / mol.atomCount()) / mol.mass());
  EXPECT_DOUBLE_EQ(center.z(), (-4.0 * Avogadro::Core::Elements::mass(3) / mol.atomCount()) / mol.mass());

  a8.setAtomicNumber(9);
  center = mol.centerOfMass();
  EXPECT_DOUBLE_EQ(center.x(), ((2.0 * Avogadro::Core::Elements::mass(2) + 1.0 * Avogadro::Core::Elements::mass(3)) / mol.atomCount()) / mol.mass());
  EXPECT_DOUBLE_EQ(center.y(), (3.0 * Avogadro::Core::Elements::mass(3) / mol.atomCount()) / mol.mass());
  EXPECT_DOUBLE_EQ(center.z(), (-4.0 * Avogadro::Core::Elements::mass(3) / mol.atomCount()) / mol.mass());
}

TEST_F(MoleculeTest, radius)
{
  Molecule mol;
  EXPECT_DOUBLE_EQ(mol.radius(), 0.0);
  Atom a = mol.addAtom(8);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(0.0, 0.0, 0.0));
  EXPECT_DOUBLE_EQ(mol.radius(), 0.0);
  a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(2.0, 0.0, -1.0));
  a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(1.0, 3.0, -2.0));
  EXPECT_DOUBLE_EQ(mol.radius(), sqrt(3.));
}

TEST_F(MoleculeTest, bestFitPlane)
{
  Array<Avogadro::Vector3> coords;
  coords.push_back(Avogadro::Vector3(0.0, 1.0, 1.0));
  coords.push_back(Avogadro::Vector3(0.0, 1.0, -1.0));
  coords.push_back(Avogadro::Vector3(0.0, -1.0, 1.0));
  coords.push_back(Avogadro::Vector3(0.0, -1.0, -1.0));
  std::pair<Avogadro::Vector3, Avogadro::Vector3> bestFitPlane =
    Molecule::bestFitPlane(coords);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.x(), 0.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.y(), 0.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.z(), 0.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.x(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.y(), 0.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.z(), 0.0);

  coords.clear();

  coords.push_back(Avogadro::Vector3(3.0, 0.0, 0.0));
  coords.push_back(Avogadro::Vector3(0.0, 3.0, 0.0));
  coords.push_back(Avogadro::Vector3(0.0, 0.0, 3.0));
  bestFitPlane = Molecule::bestFitPlane(coords);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.x(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.y(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.z(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.x(), -sqrt(3.) / 3.);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.y(), -sqrt(3.) / 3.);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.z(), -sqrt(3.) / 3.);

  Molecule mol;
  Atom a = mol.addAtom(8);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(3.0, 0.0, 0.0));
  a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(0.0, 3.0, 0.0));
  a = mol.addAtom(1);
  mol.setAtomPosition3d(a.index(), Avogadro::Vector3(0.0, 0.0, 3.0));
  bestFitPlane = mol.bestFitPlane();
  EXPECT_DOUBLE_EQ(bestFitPlane.first.x(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.y(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.first.z(), 1.0);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.x(), -sqrt(3.) / 3.);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.y(), -sqrt(3.) / 3.);
  EXPECT_DOUBLE_EQ(bestFitPlane.second.z(), -sqrt(3.) / 3.);
}

TEST_F(MoleculeTest, persistentBond)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  Atom a4 = molecule.addAtom(8);
  Bond b[5];
  b[0] = molecule.addBond(a1, a2, 1);
  b[1] = molecule.addBond(a1, a3, 2);
  b[2] = molecule.addBond(a1, a4, 3);
  b[3] = molecule.addBond(a4, a3, 2);
  b[4] = molecule.addBond(a2, a3, 1);

  Molecule::PersistentBondType pbond[5];
  for (int i = 0; i < 4; ++i)
    pbond[i].set(b[i]);
  pbond[4].set(&molecule, molecule.bondUniqueId(b[4]));
  EXPECT_EQ(pbond[0].bond().order(), 1);
  EXPECT_EQ(pbond[1].bond().order(), 2);
  EXPECT_EQ(pbond[2].bond().order(), 3);
  EXPECT_EQ(pbond[3].bond().order(), 2);
  EXPECT_EQ(pbond[4].bond().order(), 1);
  molecule.removeBond(b[2]);
  EXPECT_EQ(pbond[0].bond().order(), 1);
  EXPECT_EQ(pbond[1].bond().order(), 2);
  EXPECT_TRUE(pbond[4].isValid());
  EXPECT_FALSE(pbond[2].isValid());
  EXPECT_EQ(pbond[3].bond().order(), 2);
  EXPECT_EQ(pbond[4].bond().order(), 1);
  EXPECT_EQ(pbond[3].bond(), b[3]);
}

TEST_F(MoleculeTest, persistentBondRestore)
{
  Molecule molecule;
  Atom a1 = molecule.addAtom(5);
  Atom a2 = molecule.addAtom(6);
  Atom a3 = molecule.addAtom(7);
  Atom a4 = molecule.addAtom(8);
  Bond b[5];
  b[0] = molecule.addBond(a1, a2, 1);
  b[1] = molecule.addBond(a1, a3, 2);
  b[2] = molecule.addBond(a1, a4, 3);
  b[3] = molecule.addBond(a4, a3, 2);
  b[4] = molecule.addBond(a2, a3, 1);

  Molecule::PersistentBondType pbond[5];
  for (int i = 0; i < 5; ++i)
    pbond[i].set(&molecule, molecule.bondUniqueId(b[i]));
  molecule.removeBond(b[2]);
  EXPECT_EQ(pbond[0].bond().order(), 1);
  EXPECT_EQ(pbond[1].bond().order(), 2);
  EXPECT_TRUE(pbond[4].isValid());
  EXPECT_FALSE(pbond[2].isValid());
  EXPECT_EQ(pbond[3].bond().order(), 2);
  EXPECT_EQ(pbond[4].bond().order(), 1);
  EXPECT_EQ(pbond[3].bond(), b[3]);
  molecule.addBond(a1, a4, 3, pbond[2].uniqueIdentifier());
  EXPECT_TRUE(pbond[2].isValid());
  EXPECT_EQ(pbond[2].bond().order(), 3);
}

TEST_F(MoleculeTest, copy)
{
  Molecule copy(m_testMolecule);
  assertEqual(m_testMolecule, copy);

  EXPECT_EQ(copy.atomByUniqueId(0).atomicNumber(), 8);
  EXPECT_EQ(copy.atomByUniqueId(1).atomicNumber(), 1);
  EXPECT_EQ(copy.atomByUniqueId(2).atomicNumber(), 1);
  EXPECT_FALSE(copy.atomByUniqueId(3).isValid());
  EXPECT_EQ(copy.bondByUniqueId(0).atom1().atomicNumber(), 8);
  EXPECT_EQ(copy.bondByUniqueId(0).atom2().atomicNumber(), 1);
  EXPECT_EQ(copy.bondByUniqueId(1).atom1().atomicNumber(), 8);
  EXPECT_EQ(copy.bondByUniqueId(1).atom2().atomicNumber(), 1);
  EXPECT_FALSE(copy.bondByUniqueId(2).isValid());
}

TEST_F(MoleculeTest, assignment)
{
  Molecule assign;
  assign = m_testMolecule;
  assertEqual(m_testMolecule, assign);

  EXPECT_EQ(assign.atomByUniqueId(0).atomicNumber(), 8);
  EXPECT_EQ(assign.atomByUniqueId(1).atomicNumber(), 1);
  EXPECT_EQ(assign.atomByUniqueId(2).atomicNumber(), 1);
  EXPECT_FALSE(assign.atomByUniqueId(3).isValid());
  EXPECT_EQ(assign.bondByUniqueId(0).atom1().atomicNumber(), 8);
  EXPECT_EQ(assign.bondByUniqueId(0).atom2().atomicNumber(), 1);
  EXPECT_EQ(assign.bondByUniqueId(1).atom1().atomicNumber(), 8);
  EXPECT_EQ(assign.bondByUniqueId(1).atom2().atomicNumber(), 1);
  EXPECT_FALSE(assign.bondByUniqueId(2).isValid());
}

TEST_F(MoleculeTest, baseAssignment)
{
  // Create a base molecule
  Avogadro::Core::Molecule baseMolecule;
  Atom o1 = baseMolecule.addAtom(8);
  Atom h2 = baseMolecule.addAtom(1);
  Atom h3 = baseMolecule.addAtom(1);
  Bond b[2];
  b[0] = baseMolecule.addBond(o1, h2, 1);
  b[1] = baseMolecule.addBond(o1, h3, 2);

  o1.setPosition3d(Avogadro::Vector3(0, 0, 0));
  h2.setPosition3d(Avogadro::Vector3(0.6, -0.5, 0));
  h3.setPosition3d(Avogadro::Vector3(-0.6, -0.5, 0));

  o1.setPosition2d(Avogadro::Vector2(0, 0));
  h2.setPosition2d(Avogadro::Vector2(0.6, -0.5));
  h3.setPosition2d(Avogadro::Vector2(-0.6, -0.5));

  // Add some data
  Avogadro::Core::VariantMap data;
  data.setValue("test", Avogadro::Core::Variant("test"));
  baseMolecule.setDataMap(data);

  Mesh* mesh = baseMolecule.addMesh();

  Array<Avogadro::Vector3f> vertices;
  Array<Avogadro::Vector3f> normals;
  Array<Color3f> colors;

  Color3f color = Color3f(23, 23, 23);
  colors.push_back(color);

  Avogadro::Vector3f vec(1.2f, 1.3f, 1.4f);

  vertices.push_back(vec);
  normals.push_back(vec);

  mesh->setColors(colors);
  mesh->setNormals(normals);
  mesh->setVertices(vertices);
  mesh->setIsoValue(1.2f);
  mesh->setName("testmesh");
  mesh->setOtherMesh(1);
  mesh->setStable(false);

  Avogadro::QtGui::Molecule qtMolecule;

  qtMolecule.addAtom(6);
  Atom a1 = qtMolecule.addAtom(4);
  Atom a2 = qtMolecule.addAtom(5);
  qtMolecule.addBond(a1, a2);

  qtMolecule = baseMolecule;

  assertEqual(baseMolecule, qtMolecule);

  // Check the ids have reset
  EXPECT_EQ(qtMolecule.atomByUniqueId(0).atomicNumber(), o1.atomicNumber());
  EXPECT_EQ(qtMolecule.atomByUniqueId(1).atomicNumber(), h2.atomicNumber());
  EXPECT_EQ(qtMolecule.atomByUniqueId(2).atomicNumber(), h3.atomicNumber());
  EXPECT_FALSE(qtMolecule.atomByUniqueId(3).isValid());
  EXPECT_EQ(qtMolecule.bondByUniqueId(0).atom1().atomicNumber(),
            b[0].atom1().atomicNumber());
  EXPECT_EQ(qtMolecule.bondByUniqueId(0).atom2().atomicNumber(),
            b[0].atom2().atomicNumber());
  EXPECT_EQ(qtMolecule.bondByUniqueId(1).atom1().atomicNumber(),
            b[1].atom1().atomicNumber());
  EXPECT_EQ(qtMolecule.bondByUniqueId(1).atom2().atomicNumber(),
            b[1].atom2().atomicNumber());
  EXPECT_FALSE(qtMolecule.bondByUniqueId(2).isValid());
}

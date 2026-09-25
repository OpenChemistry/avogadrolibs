/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <algorithm>
#include <functional>
#include <random>
#include <tuple>
#include <utility>
#include <vector>

using Avogadro::Index;
using Avogadro::Real;
using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::QtGui::Molecule;
using Avogadro::QtGui::RWMolecule;

// TODO move this to an algorithms header
#include <avogadro/core/elements.h>
#include <map>
#include <sstream>
#include <string>

using namespace std::string_literals;

template <class MoleculeType>
std::string formula(const MoleculeType& mol)
{
  // Adapted from chemkit:
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = mol.atomicNumbers().begin(),
                                            itEnd = mol.atomicNumbers().end();
       it != itEnd; ++it) {
    composition[*it]++;
  }

  std::stringstream result;
  std::map<unsigned char, size_t>::iterator iter;

  // Carbons first
  iter = composition.find(6);
  if (iter != composition.end()) {
    result << "C";
    if (iter->second > 1)
      result << iter->second;
    composition.erase(iter);

    // If carbon is present, hydrogens are next.
    iter = composition.find(1);
    if (iter != composition.end()) {
      result << "H";
      if (iter->second > 1)
        result << iter->second;
      composition.erase(iter);
    }
  }

  // The rest:
  iter = composition.begin();
  while (iter != composition.end()) {
    result << Avogadro::Core::Elements::symbol(iter->first);
    if (iter->second > 1)
      result << iter->second;
    ++iter;
  }

  return result.str();
}

TEST(RWMoleculeTest, addAtom)
{
  Molecule m;
  RWMolecule mol(m);

  mol.addAtom(1); // H
  mol.addAtom(5); // B
  mol.addAtom(6); // C
  mol.addAtom(7); // N
  mol.addAtom(8); // O

  EXPECT_EQ(5, mol.atomCount());
  EXPECT_EQ("CHBNO"s, formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ("CHBN"s, formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ("CHB"s, formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(2, mol.atomCount());
  EXPECT_EQ("HB"s, formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(1, mol.atomCount());
  EXPECT_EQ("H"s, formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(0, mol.atomCount());

  EXPECT_FALSE(mol.undoStack().canUndo());

  mol.undoStack().redo();
  EXPECT_EQ(1, mol.atomCount());
  EXPECT_EQ("H"s, formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(2, mol.atomCount());
  EXPECT_EQ("HB"s, formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ("CHB"s, formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ("CHBN"s, formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(5, mol.atomCount());
  EXPECT_EQ("CHBNO"s, formula(mol));

  EXPECT_FALSE(mol.undoStack().canRedo());

  // Are the uids what we expect?
  for (Index i = 0; i < 5; ++i)
    EXPECT_EQ(i, mol.atomUniqueId(i));
}

TEST(RWMoleculeTest, removeAtom)
{
  Molecule m;
  RWMolecule mol(m);
  typedef RWMolecule::AtomType Atom;

  Atom a0 = mol.addAtom(1); // H
  Atom a1 = mol.addAtom(2); // He
  Atom a2 = mol.addAtom(3); // Li
  Atom a3 = mol.addAtom(4); // Be
  Atom a4 = mol.addAtom(5); // B

  const Vector3 pos(Real(1), Real(2), Real(3));
  mol.setAtomPosition3d(0, pos);

  ASSERT_EQ(5, mol.atomCount());
  ASSERT_EQ("HHeLiBeB"s, formula(mol));

  // Add some bonds to ensure that they are properly added/removed when a bonded
  // atom is removed.
  ASSERT_TRUE(mol.addBond(a0, a1, 0).isValid());
  ASSERT_TRUE(mol.addBond(a1, a2, 1).isValid());
  ASSERT_TRUE(mol.addBond(a2, a3, 2).isValid());
  ASSERT_TRUE(mol.addBond(a3, a4, 3).isValid());
  ASSERT_TRUE(mol.addBond(a0, a2, 4).isValid());
  ASSERT_TRUE(mol.addBond(a1, a3, 5).isValid());
  ASSERT_TRUE(mol.addBond(a2, a4, 6).isValid());
  ASSERT_TRUE(mol.addBond(a0, a3, 7).isValid());
  ASSERT_TRUE(mol.addBond(a1, a4, 8).isValid());
  ASSERT_TRUE(mol.addBond(a0, a4, 9).isValid());

  ASSERT_EQ(10, mol.bondCount());

  EXPECT_TRUE(mol.removeAtom(2));
  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ(6, mol.bondCount());
  EXPECT_EQ("HHeBeB"s, formula(mol));
  EXPECT_FALSE(mol.atomByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(1).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(4).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(6).isValid());

  EXPECT_TRUE(mol.removeAtom(0));
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ(3, mol.bondCount());
  EXPECT_EQ("HeBeB"s, formula(mol));
  EXPECT_FALSE(mol.atomByUniqueId(0).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(0).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(7).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(9).isValid());

  // atom 0 was the only one with a position, so all positions should be 0,0,0:
  for (Index i = 0; i < mol.atomCount(); ++i) {
    EXPECT_EQ(Real(0), mol.atomPosition3d(i).x()) << " for atom index " << i;
    EXPECT_EQ(Real(0), mol.atomPosition3d(i).y()) << " for atom index " << i;
    EXPECT_EQ(Real(0), mol.atomPosition3d(i).z()) << " for atom index " << i;
  }

  mol.undoStack().undo();

  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ(6, mol.bondCount());
  EXPECT_EQ("HHeBeB"s, formula(mol));
  EXPECT_FALSE(mol.atomByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(1).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(4).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(6).isValid());

  EXPECT_TRUE(mol.atomByUniqueId(0).isValid());
  EXPECT_TRUE(mol.bondByUniqueId(0).isValid());
  EXPECT_TRUE(mol.bondByUniqueId(7).isValid());
  EXPECT_TRUE(mol.bondByUniqueId(9).isValid());

  EXPECT_EQ(pos.x(), mol.atomPosition3d(0).x());
  EXPECT_EQ(pos.y(), mol.atomPosition3d(0).y());
  EXPECT_EQ(pos.z(), mol.atomPosition3d(0).z());

  mol.undoStack().undo();

  ASSERT_EQ(5, mol.atomCount());
  ASSERT_EQ(10, mol.bondCount());
  ASSERT_EQ("HHeLiBeB"s, formula(mol));

  for (Index i = 0; i < mol.atomCount(); ++i) {
    EXPECT_EQ(static_cast<unsigned char>(i + 1), mol.atomicNumber(i));
    EXPECT_EQ(i, mol.atomUniqueId(i));
  }

#define VALIDATE_BOND(ind, atom1, atom2, order, uid)                           \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind));    \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind));            \
  EXPECT_EQ(uid, mol.bondUniqueId(ind))

  VALIDATE_BOND(0, 0, 1, 0, 0);
  VALIDATE_BOND(1, 1, 2, 1, 1);
  VALIDATE_BOND(2, 2, 3, 2, 2);
  VALIDATE_BOND(3, 3, 4, 3, 3);
  VALIDATE_BOND(4, 0, 2, 4, 4);
  VALIDATE_BOND(5, 1, 3, 5, 5);
  VALIDATE_BOND(6, 2, 4, 6, 6);
  VALIDATE_BOND(7, 0, 3, 7, 7);
  VALIDATE_BOND(8, 1, 4, 8, 8);
  VALIDATE_BOND(9, 0, 4, 9, 9);
#undef VALIDATE_BOND
}

TEST(RWMoleculeTest, clearAtoms)
{
  Molecule m;
  RWMolecule mol(m);
  typedef RWMolecule::AtomType Atom;

  Atom a0 = mol.addAtom(1); // H
  Atom a1 = mol.addAtom(2); // He
  Atom a2 = mol.addAtom(3); // Li
  Atom a3 = mol.addAtom(4); // Be
  Atom a4 = mol.addAtom(5); // B

  const Vector3 pos(Real(1), Real(2), Real(3));
  mol.setAtomPosition3d(0, pos);

  ASSERT_EQ(5, mol.atomCount());
  ASSERT_EQ("HHeLiBeB"s, formula(mol));

  // Add some bonds to ensure that they are properly added/removed when a bonded
  // atom is removed.
  ASSERT_TRUE(mol.addBond(a0, a1, 0).isValid());
  ASSERT_TRUE(mol.addBond(a1, a2, 1).isValid());
  ASSERT_TRUE(mol.addBond(a2, a3, 2).isValid());
  ASSERT_TRUE(mol.addBond(a3, a4, 3).isValid());
  ASSERT_TRUE(mol.addBond(a0, a2, 4).isValid());
  ASSERT_TRUE(mol.addBond(a1, a3, 5).isValid());
  ASSERT_TRUE(mol.addBond(a2, a4, 6).isValid());
  ASSERT_TRUE(mol.addBond(a0, a3, 7).isValid());
  ASSERT_TRUE(mol.addBond(a1, a4, 8).isValid());
  ASSERT_TRUE(mol.addBond(a0, a4, 9).isValid());

  ASSERT_EQ(10, mol.bondCount());

  mol.clearAtoms();

  EXPECT_EQ(0, mol.atomCount());
  EXPECT_EQ(0, mol.bondCount());

  mol.undoStack().undo();

  ASSERT_EQ(5, mol.atomCount());
  ASSERT_EQ(10, mol.bondCount());
  ASSERT_EQ("HHeLiBeB"s, formula(mol));

  for (Index i = 0; i < mol.atomCount(); ++i) {
    EXPECT_EQ(static_cast<unsigned char>(i + 1), mol.atomicNumber(i));
    EXPECT_EQ(i, mol.atomUniqueId(i));
  }

#define VALIDATE_BOND(ind, atom1, atom2, order, uid)                           \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind));            \
  EXPECT_EQ(uid, mol.bondUniqueId(ind))

  // This is disabled because the pair may come in any order
  //   EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind));

  VALIDATE_BOND(0, 0, 1, 0, 0);
  VALIDATE_BOND(1, 1, 2, 1, 1);
  VALIDATE_BOND(2, 2, 3, 2, 2);
  VALIDATE_BOND(3, 3, 4, 3, 3);
  VALIDATE_BOND(4, 0, 2, 4, 4);
  VALIDATE_BOND(5, 1, 3, 5, 5);
  VALIDATE_BOND(6, 2, 4, 6, 6);
  VALIDATE_BOND(7, 0, 3, 7, 7);
  VALIDATE_BOND(8, 1, 4, 8, 8);
  VALIDATE_BOND(9, 0, 4, 9, 9);
#undef VALIDATE_BOND
}

TEST(RWMoleculeTest, setAtomicNumbers)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);

  Array<unsigned char> orig(mol.atomicNumbers());
  Array<unsigned char> rep(5);
  rep[0] = 6;
  rep[0] = 7;
  rep[0] = 8;
  rep[0] = 9;
  rep[0] = 10;

  mol.setAtomicNumbers(rep);
  ASSERT_TRUE(std::equal(mol.atomicNumbers().begin(), mol.atomicNumbers().end(),
                         rep.begin(), rep.end()));

  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomicNumbers().begin(), mol.atomicNumbers().end(),
                         orig.begin(), orig.end()));
}

TEST(RWMoleculeTest, setAtomicNumber)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);

  mol.setAtomicNumber(0, 6);
  mol.setAtomicNumber(2, 7);
  mol.setAtomicNumber(4, 8);

  EXPECT_EQ(6, mol.atomicNumber(0));
  EXPECT_EQ(2, mol.atomicNumber(1));
  EXPECT_EQ(7, mol.atomicNumber(2));
  EXPECT_EQ(4, mol.atomicNumber(3));
  EXPECT_EQ(8, mol.atomicNumber(4));

  mol.undoStack().undo();
  EXPECT_EQ(5, mol.atomicNumber(4));
  mol.undoStack().undo();
  EXPECT_EQ(3, mol.atomicNumber(2));
  mol.undoStack().undo();
  EXPECT_EQ(1, mol.atomicNumber(0));
}

TEST(RWMoleculeTest, setAtomPositions3d)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);

  // These will all be (0, 0, 0)
  auto oldPositions = mol.atomPositions3d();
  mol.undoStack().clear();

  Array<Vector3> pos;
  Real gen = 1;
  pos.push_back(Vector3(gen, gen, gen));
  gen++;
  pos.push_back(Vector3(gen, gen, gen));
  gen++;
  pos.push_back(Vector3(gen, gen, gen));
  gen++;
  pos.push_back(Vector3(gen, gen, gen));
  gen++;
  pos.push_back(Vector3(gen, gen, gen));
  gen++;

  mol.setAtomPositions3d(pos);
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin(), pos.end()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), oldPositions.begin(),
                         oldPositions.end()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin(), pos.end()));
  mol.undoStack().undo();

  // Test merging for interactive edits:
  mol.setInteractive(true);
  mol.setAtomPositions3d(pos);
  for (Array<Vector3>::iterator it = pos.begin(), itEnd = pos.end();
       it != itEnd; ++it) {
    it->x() += static_cast<Real>(pos.size());
    it->y() += static_cast<Real>(pos.size());
    it->z() += static_cast<Real>(pos.size());
  }
  mol.setAtomPositions3d(pos);
  mol.setInteractive(false);

  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin(), pos.end()));
  EXPECT_EQ(1, mol.undoStack().count());
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), oldPositions.begin(),
                         oldPositions.end()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin(), pos.end()));
}

TEST(RWMoleculeTest, setAtomPosition3d)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);
  mol.undoStack().clear();

  // The positions will not be empty here because they are added when
  // atoms are added.
  mol.setAtomPosition3d(0, Vector3(Real(1), Real(2), Real(3)));
  EXPECT_EQ(mol.atomicNumbers().size(), mol.atomPositions3d().size());
  EXPECT_EQ(Real(1), mol.atomPosition3d(0).x());
  EXPECT_EQ(Real(2), mol.atomPosition3d(0).y());
  EXPECT_EQ(Real(3), mol.atomPosition3d(0).z());
  for (Index i = 1; i < 5; ++i)
    EXPECT_EQ(Vector3::Zero(), mol.atomPosition3d(i));

  mol.undoStack().undo();
  for (Index i = 0; i < 5; ++i)
    EXPECT_EQ(Vector3::Zero(), mol.atomPosition3d(i));

  mol.undoStack().redo();
  EXPECT_EQ(Real(1), mol.atomPosition3d(0).x());
  EXPECT_EQ(Real(2), mol.atomPosition3d(0).y());
  EXPECT_EQ(Real(3), mol.atomPosition3d(0).z());
  for (Index i = 1; i < 5; ++i)
    EXPECT_EQ(Vector3::Zero(), mol.atomPosition3d(i));

  mol.undoStack().undo();
  mol.undoStack().clear();

  // Test command merging for interactive editing:
  mol.setInteractive(true);
  mol.setAtomPosition3d(0, Vector3(Real(1), Real(2), Real(3)));
  mol.setAtomPosition3d(3, Vector3(Real(4), Real(5), Real(6)));
  mol.setAtomPosition3d(0, Vector3(Real(7), Real(8), Real(9)));
  mol.setAtomPosition3d(1, Vector3(Real(6), Real(4), Real(2)));
  mol.setInteractive(false);

  Array<Vector3> pos(mol.atomPositions3d());
  EXPECT_EQ(Vector3(Real(7), Real(8), Real(9)), pos[0]);
  EXPECT_EQ(Vector3(Real(6), Real(4), Real(2)), pos[1]);
  EXPECT_EQ(Vector3::Zero(), pos[2]);
  EXPECT_EQ(Vector3(Real(4), Real(5), Real(6)), pos[3]);
  EXPECT_EQ(Vector3::Zero(), pos[4]);

  EXPECT_EQ(1, mol.undoStack().count());
  mol.undoStack().undo();
  for (Index i = 1; i < 5; ++i)
    EXPECT_EQ(Vector3::Zero(), mol.atomPosition3d(i));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(pos.begin(), pos.end(), mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end()));
}

TEST(RWMoleculeTest, addBond)
{
  Molecule m;
  RWMolecule mol(m);
  RWMolecule::AtomType a0 = mol.addAtom(1);
  RWMolecule::AtomType a1 = mol.addAtom(2);
  mol.addAtom(3);
  mol.undoStack().clear();

  ASSERT_EQ(0, mol.bondCount());

  EXPECT_TRUE(mol.addBond(a0, a1).isValid());
  EXPECT_TRUE(mol.addBond(1, 2, 2).isValid());
  EXPECT_FALSE(mol.addBond(1, 8, 2).isValid());

  EXPECT_EQ(2, mol.bondCount());
  mol.undoStack().undo();
  EXPECT_EQ(1, mol.bondCount());
  EXPECT_TRUE(mol.bond(a0, a1).isValid());
  EXPECT_TRUE(mol.bond(a1, a0).isValid());
  EXPECT_TRUE(mol.bond(1, 0).isValid());
  EXPECT_FALSE(mol.bond(1, 2).isValid());
  mol.undoStack().redo();
  EXPECT_EQ(2, mol.bondCount());
  EXPECT_TRUE(mol.bond(1, 0).isValid());
  EXPECT_TRUE(mol.bond(1, 2).isValid());
  EXPECT_EQ(1, mol.bondOrder(0));
  EXPECT_EQ(2, mol.bondOrder(1));
}

TEST(RWMoleculeTest, removeBond)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  mol.undoStack().clear();

#define VALIDATE_BOND(ind, atom1, atom2, order, uid)                           \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind));    \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind));            \
  EXPECT_EQ(uid, mol.bondUniqueId(ind))

  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

  mol.removeBond(mol.atom(1), mol.atom(2));
  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 2, 3, 3, 2);

  mol.removeBond(1);
  VALIDATE_BOND(0, 0, 1, 1, 0);

  mol.undoStack().undo();
  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 2, 3, 3, 2);

  mol.removeBond(mol.bond(0));
  VALIDATE_BOND(0, 2, 3, 3, 2);

  mol.undoStack().undo();
  mol.undoStack().undo();

  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

#undef VALIDATE_BOND
}

TEST(RWMoleculeTest, clearBonds)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  mol.undoStack().clear();

  Array<std::pair<Index, Index>> pairs(mol.bondPairs());
  Array<unsigned char> ords(mol.bondOrders());

  mol.clearBonds();
  EXPECT_EQ(0, mol.bondCount());

  mol.undoStack().undo();
  EXPECT_EQ(3, mol.bondCount());
  EXPECT_TRUE(std::equal(pairs.begin(), pairs.end(), mol.bondPairs().begin(),
                         mol.bondPairs().end()));
  EXPECT_TRUE(std::equal(ords.begin(), ords.end(), mol.bondOrders().begin(),
                         mol.bondOrders().end()));
}

TEST(RWMoleculeTest, setBondOrders)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  ASSERT_EQ(1, mol.bondOrder(0));
  ASSERT_EQ(2, mol.bondOrder(1));
  ASSERT_EQ(3, mol.bondOrder(2));
  mol.undoStack().clear();

  Array<unsigned char> old(mol.bondOrders());
  Array<unsigned char> rep(old);
  for (Array<unsigned char>::iterator it = rep.begin(), itEnd = rep.end();
       it != itEnd; ++it) {
    *it += rep.size();
  }

  mol.setBondOrders(rep);
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondOrders().begin(),
                         mol.bondOrders().end()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(old.begin(), old.end(), mol.bondOrders().begin(),
                         mol.bondOrders().end()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondOrders().begin(),
                         mol.bondOrders().end()));
}

TEST(RWMoleculeTest, setBondOrder)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  ASSERT_EQ(1, mol.bondOrder(0));
  ASSERT_EQ(2, mol.bondOrder(1));
  ASSERT_EQ(3, mol.bondOrder(2));
  mol.undoStack().clear();

  // This undo behavior is a little different -- sequential changes to the
  // same bond's bond order are always merged.
  mol.setBondOrder(0, 2);
  mol.setBondOrder(0, 3);
  EXPECT_EQ(1, mol.undoStack().count());

  mol.setBondOrder(2, 2);
  mol.setBondOrder(2, 1);
  EXPECT_EQ(2, mol.undoStack().count());

#define VALIDATE_BOND(ind, atom1, atom2, order, uid)                           \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind));    \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind));            \
  EXPECT_EQ(uid, mol.bondUniqueId(ind))

  VALIDATE_BOND(0, 0, 1, 3, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 1, 2);

  mol.undoStack().undo();
  VALIDATE_BOND(0, 0, 1, 3, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

  mol.undoStack().undo();
  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

  mol.undoStack().redo();
  mol.undoStack().redo();
  VALIDATE_BOND(0, 0, 1, 3, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 1, 2);
#undef VALIDATE_BOND
}

TEST(RWMoleculeTest, setBondPairs)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  ASSERT_EQ(Molecule::makeBondPair(0, 1), mol.bondPair(0));
  ASSERT_EQ(Molecule::makeBondPair(1, 2), mol.bondPair(1));
  ASSERT_EQ(Molecule::makeBondPair(2, 3), mol.bondPair(2));
  mol.undoStack().clear();

  typedef std::pair<Index, Index> BondPair;
  Array<BondPair> old(mol.bondPairs());
  Array<BondPair> rep(old);
  for (Array<BondPair>::iterator it = rep.begin(), itEnd = rep.end();
       it != itEnd; ++it) {
    ++it->second;
  }

  mol.setBondPairs(rep);
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondPairs().begin(),
                         mol.bondPairs().end()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(old.begin(), old.end(), mol.bondPairs().begin(),
                         mol.bondPairs().end()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondPairs().begin(),
                         mol.bondPairs().end()));
}

TEST(RWMoleculeTest, setBondPair)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(1);
  mol.addAtom(2);
  mol.addAtom(3);
  mol.addAtom(4);
  mol.addAtom(5);
  mol.addBond(0, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  ASSERT_EQ(3, mol.bondCount());
  ASSERT_EQ(Molecule::makeBondPair(0, 1), mol.bondPair(0));
  ASSERT_EQ(Molecule::makeBondPair(1, 2), mol.bondPair(1));
  ASSERT_EQ(Molecule::makeBondPair(2, 3), mol.bondPair(2));
  mol.undoStack().clear();

  mol.setBondPair(0, Molecule::makeBondPair(0, 2));
  mol.setBondPair(2, Molecule::makeBondPair(2, 4));

#define VALIDATE_BOND(ind, atom1, atom2, order, uid)                           \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind));    \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind));            \
  EXPECT_EQ(uid, mol.bondUniqueId(ind))

  VALIDATE_BOND(0, 0, 2, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 4, 3, 2);

  mol.undoStack().undo();
  VALIDATE_BOND(0, 0, 2, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

  mol.undoStack().undo();
  VALIDATE_BOND(0, 0, 1, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 3, 3, 2);

  mol.undoStack().redo();
  mol.undoStack().redo();
  VALIDATE_BOND(0, 0, 2, 1, 0);
  VALIDATE_BOND(1, 1, 2, 2, 1);
  VALIDATE_BOND(2, 2, 4, 3, 2);
#undef VALIDATE_BOND
}

TEST(RWMoleculeTest, AtomType)
{
  Molecule m;
  RWMolecule mol(m);
  typedef RWMolecule::AtomType Atom;
  Atom a0 = mol.addAtom(1);
  Atom a1 = mol.addAtom(2);

  EXPECT_TRUE(a0.isValid());
  EXPECT_FALSE(Atom().isValid());
  EXPECT_FALSE(Atom(&mol, 2).isValid());

  EXPECT_EQ(&mol, a0.molecule());
  EXPECT_EQ(0, a0.index());

  EXPECT_EQ(1, a0.atomicNumber());
  EXPECT_EQ(1, mol.atomicNumber(0));
  EXPECT_EQ(2, a1.atomicNumber());
  EXPECT_EQ(2, mol.atomicNumber(1));

  a0.setPosition3d(Vector3(Real(3), Real(4), Real(5)));
  a1.setPosition3d(Vector3(Real(6), Real(7), Real(8)));

  EXPECT_EQ(Vector3(Real(3), Real(4), Real(5)), a0.position3d());
  EXPECT_EQ(Vector3(Real(3), Real(4), Real(5)), mol.atomPosition3d(0));
  EXPECT_EQ(Vector3(Real(6), Real(7), Real(8)), a1.position3d());
  EXPECT_EQ(Vector3(Real(6), Real(7), Real(8)), mol.atomPosition3d(1));

  Atom other(&mol, 0);
  EXPECT_EQ(a0, other);
  EXPECT_NE(a1, other);
}

TEST(RWMoleculeTest, BondType)
{
  Molecule m;
  RWMolecule mol(m);
  typedef RWMolecule::AtomType Atom;
  typedef RWMolecule::BondType Bond;
  Atom a0 = mol.addAtom(1);
  Atom a1 = mol.addAtom(2);
  Atom a2 = mol.addAtom(3);

  Bond b0 = mol.addBond(a0, a1);
  Bond b1 = mol.addBond(1, 2);
  Bond invalid = mol.addBond(0, 9);

  EXPECT_TRUE(b0.isValid());
  EXPECT_FALSE(invalid.isValid());
  EXPECT_FALSE(Bond().isValid());
  EXPECT_FALSE(Bond(&mol, 3).isValid());

  EXPECT_EQ(&mol, b0.molecule());
  EXPECT_EQ(0, b0.index());

  EXPECT_EQ(a0, b0.atom1());
  EXPECT_EQ(a2, b1.atom2());

  b1.setOrder(2);
  EXPECT_EQ(2, b1.order());
  EXPECT_EQ(2, mol.bondOrder(1));

  Bond other(&mol, 0);
  EXPECT_EQ(b0, other);
  EXPECT_NE(b1, other);
}

TEST(RWMoleculeTest, MoleculeToRWMolecule)
{
  Molecule mol;
  typedef Molecule::AtomType Atom;
  typedef Molecule::BondType Bond;
  Atom a0 = mol.addAtom(1);
  Atom a1 = mol.addAtom(6);
  Atom a2 = mol.addAtom(9);
  Bond b0 = mol.addBond(a0, a2);
  a1.setPosition3d(Vector3(0, 6, 9));
  b0.setOrder(3);

  RWMolecule rwmol(mol, nullptr);
  EXPECT_EQ(rwmol.atomCount(), mol.atomCount());
  EXPECT_EQ(rwmol.bondCount(), mol.bondCount());
  EXPECT_EQ(rwmol.atom(2).atomicNumber(), mol.atom(2).atomicNumber());
  EXPECT_EQ(rwmol.bond(0).order(), mol.bond(0).order());
}

namespace {

// A small molecule whose atoms are each distinguishable by every atom-indexed
// property the reorder has to carry along.
void buildDistinctAtoms(RWMolecule& mol, Index count)
{
  for (Index i = 0; i < count; ++i) {
    mol.addAtom(static_cast<unsigned char>(i + 1));
    mol.setAtomPosition3d(i, Vector3(Real(i), Real(10 * i), Real(100 * i)));
    mol.setAtomLabel(i, "atom" + std::to_string(i));
    mol.setFormalCharge(i, static_cast<signed char>(i));
  }
}

// Assert that atom @p at holds the properties originally given to atom
// @p from by buildDistinctAtoms().
void expectAtomIs(const RWMolecule& mol, Index at, Index from)
{
  EXPECT_EQ(static_cast<unsigned char>(from + 1), mol.atomicNumber(at))
    << "atom " << at;
  EXPECT_EQ(Vector3(Real(from), Real(10 * from), Real(100 * from)),
            mol.atomPosition3d(at))
    << "atom " << at;
  EXPECT_EQ("atom" + std::to_string(from), mol.atomLabel(at)) << "atom " << at;
  EXPECT_EQ(static_cast<signed char>(from), mol.formalCharge(at))
    << "atom " << at;
}

} // namespace

TEST(RWMoleculeTest, reorderAtomsIdentity)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 4);
  const int before = mol.undoStack().count();

  Array<Index> order(4);
  for (Index i = 0; i < 4; ++i)
    order[i] = i;

  EXPECT_TRUE(mol.reorderAtoms(order));
  for (Index i = 0; i < 4; ++i)
    expectAtomIs(mol, i, i);

  // Nothing moved, so nothing should be sitting on the undo stack waiting to
  // be undone.
  EXPECT_EQ(before, mol.undoStack().count());
}

TEST(RWMoleculeTest, reorderAtomsTransposition)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 4);

  Array<Index> order(4);
  order[0] = 0;
  order[1] = 3;
  order[2] = 2;
  order[3] = 1;

  ASSERT_TRUE(mol.reorderAtoms(order));
  expectAtomIs(mol, 0, 0);
  expectAtomIs(mol, 1, 3);
  expectAtomIs(mol, 2, 2);
  expectAtomIs(mol, 3, 1);
}

TEST(RWMoleculeTest, reorderAtomsMultiCycle)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 6);

  // Two disjoint 3-cycles, so a single pass of transpositions is not enough
  // unless the bookkeeping is right.
  Array<Index> order(6);
  order[0] = 2;
  order[1] = 0;
  order[2] = 1;
  order[3] = 5;
  order[4] = 3;
  order[5] = 4;

  ASSERT_TRUE(mol.reorderAtoms(order));
  for (Index i = 0; i < 6; ++i)
    expectAtomIs(mol, i, order[i]);
}

TEST(RWMoleculeTest, reorderAtomsCarriesBondsAndSelection)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 4);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(2, 3, 3);
  mol.setAtomSelected(1, true);

  // Reverse the atoms.
  Array<Index> order(4);
  for (Index i = 0; i < 4; ++i)
    order[i] = 3 - i;
  ASSERT_TRUE(mol.reorderAtoms(order));

  // The same three bonds, with the same orders, between the same atoms --
  // which are now numbered the other way round.
  ASSERT_EQ(static_cast<Index>(3), mol.bondCount());
  EXPECT_TRUE(mol.bond(3, 2).isValid());
  EXPECT_EQ(1, mol.bond(3, 2).order());
  EXPECT_TRUE(mol.bond(2, 1).isValid());
  EXPECT_EQ(2, mol.bond(2, 1).order());
  EXPECT_TRUE(mol.bond(1, 0).isValid());
  EXPECT_EQ(3, mol.bond(1, 0).order());

  // The selected atom is still the one that was selected.
  EXPECT_TRUE(mol.atomSelected(2));
  EXPECT_FALSE(mol.atomSelected(0));
  EXPECT_FALSE(mol.atomSelected(1));
  EXPECT_FALSE(mol.atomSelected(3));
}

TEST(RWMoleculeTest, reorderAtomsKeepsUniqueIds)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 4);

  Array<Index> uids(4);
  for (Index i = 0; i < 4; ++i)
    uids[i] = mol.atomUniqueId(i);

  Array<Index> order(4);
  order[0] = 2;
  order[1] = 3;
  order[2] = 0;
  order[3] = 1;
  ASSERT_TRUE(mol.reorderAtoms(order));

  // A unique id is a handle held across edits, so it must still resolve to
  // the same atom rather than to whatever now occupies that index.
  for (Index i = 0; i < 4; ++i) {
    RWMolecule::AtomType atom = mol.atomByUniqueId(uids[order[i]]);
    ASSERT_TRUE(atom.isValid()) << "unique id for original atom " << order[i];
    EXPECT_EQ(i, atom.index()) << "original atom " << order[i];
  }
}

TEST(RWMoleculeTest, reorderAtomsUndoRedo)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 5);
  mol.addBond(0, 4, 2);

  Array<Index> order(5);
  order[0] = 4;
  order[1] = 2;
  order[2] = 0;
  order[3] = 3;
  order[4] = 1;
  ASSERT_TRUE(mol.reorderAtoms(order));

  mol.undoStack().undo();
  for (Index i = 0; i < 5; ++i)
    expectAtomIs(mol, i, i);
  EXPECT_TRUE(mol.bond(0, 4).isValid());
  EXPECT_EQ(2, mol.bond(0, 4).order());

  mol.undoStack().redo();
  for (Index i = 0; i < 5; ++i)
    expectAtomIs(mol, i, order[i]);
  EXPECT_TRUE(mol.bond(0, 2).isValid());
  EXPECT_EQ(2, mol.bond(0, 2).order());
}

TEST(RWMoleculeTest, reorderAtomsRejectsNonPermutations)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 3);
  const int before = mol.undoStack().count();

  Array<Index> tooShort(2);
  tooShort[0] = 0;
  tooShort[1] = 1;
  EXPECT_FALSE(mol.reorderAtoms(tooShort));

  Array<Index> outOfRange(3);
  outOfRange[0] = 0;
  outOfRange[1] = 1;
  outOfRange[2] = 7;
  EXPECT_FALSE(mol.reorderAtoms(outOfRange));

  Array<Index> duplicated(3);
  duplicated[0] = 2;
  duplicated[1] = 2;
  duplicated[2] = 0;
  EXPECT_FALSE(mol.reorderAtoms(duplicated));

  // A rejected order must leave the molecule and the undo stack untouched.
  for (Index i = 0; i < 3; ++i)
    expectAtomIs(mol, i, i);
  EXPECT_EQ(before, mol.undoStack().count());
}

TEST(RWMoleculeTest, reorderAtomsEmptyMolecule)
{
  Molecule m;
  RWMolecule mol(m);
  Array<Index> order(0);
  EXPECT_TRUE(mol.reorderAtoms(order));
  EXPECT_EQ(static_cast<Index>(0), mol.atomCount());
}

TEST(RWMoleculeTest, reorderAtomsCarriesResidues)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 4);

  std::string resName = "ALA";
  Index resNumber = 1;
  char chain = 'A';
  Avogadro::Core::Residue& residue = m.addResidue(resName, resNumber, chain);
  residue.addResidueAtom("N", m.atom(0));
  residue.addResidueAtom("CA", m.atom(1));
  residue.addResidueAtom("C", m.atom(2));

  // A 3-cycle over the residue's atoms, leaving the fourth atom outside it.
  Array<Index> order(4);
  order[0] = 2;
  order[1] = 0;
  order[2] = 1;
  order[3] = 3;
  ASSERT_TRUE(mol.reorderAtoms(order));

  // Each name still names the atom it was given: buildDistinctAtoms() sets
  // atomic number i + 1, so the original atom is identifiable after the move.
  const Avogadro::Core::Residue& moved = m.residue(0);
  EXPECT_EQ(1, moved.atomByName("N").atomicNumber());
  EXPECT_EQ(2, moved.atomByName("CA").atomicNumber());
  EXPECT_EQ(3, moved.atomByName("C").atomicNumber());
  EXPECT_EQ(static_cast<size_t>(3), moved.residueAtoms().size());

  // And undo puts the membership back where it started.
  mol.undoStack().undo();
  const Avogadro::Core::Residue& restored = m.residue(0);
  EXPECT_EQ(static_cast<Index>(0), restored.atomByName("N").index());
  EXPECT_EQ(static_cast<Index>(1), restored.atomByName("CA").index());
  EXPECT_EQ(static_cast<Index>(2), restored.atomByName("C").index());
}

// An index from before an atom was removed used to be written straight into
// a std::vector<bool> sized to the current atom count, corrupting the heap
// and crashing somewhere unrelated later. It has to be ignored instead.
TEST(RWMoleculeTest, setAtomSelectedIgnoresOutOfRangeIndices)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 5);
  mol.setAtomSelected(2, true);
  const int before = mol.undoStack().count();

  // Past the end, and the sentinel an invalid lookup returns.
  mol.setAtomSelected(5, true);
  mol.setAtomSelected(7, true);
  mol.setAtomSelected(Avogadro::MaxIndex, true);

  // The molecule is untouched and no command was pushed for a write that
  // could not land anywhere.
  EXPECT_EQ(before, mol.undoStack().count());
  EXPECT_EQ(static_cast<Index>(5), mol.atomCount());
  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_EQ(i == 2, mol.atomSelected(i)) << "atom " << i;

  // And the atoms themselves still hold what they were given.
  for (Index i = 0; i < 5; ++i)
    expectAtomIs(mol, i, i);
}

// Renumbering swaps atoms that are bonded to each other, which used to leave
// Graph's adjacency list naming those vertices as their own neighbours. The
// edge between them could then no longer be found, so removeEdge() returned
// without removing anything while the caller dropped the matching bond
// order -- and the molecule crashed later, in unrelated bond bookkeeping.
TEST(RWMoleculeTest, reorderThenRemoveABondedAtom)
{
  Molecule m;
  RWMolecule mol(m);

  // A central atom whose index is not first, so the renumbering has to swap
  // it with one of the atoms bonded to it.
  mol.addAtom(1, Vector3(1.0, 0.0, 0.0));
  mol.addAtom(1, Vector3(-0.333, 0.943, 0.0));
  mol.addAtom(6, Vector3(0.0, 0.0, 0.0));
  mol.addAtom(1, Vector3(-0.333, -0.471, 0.816));
  mol.addAtom(1, Vector3(-0.333, -0.471, -0.816));
  mol.addBond(2, 0, 1);
  mol.addBond(2, 1, 1);
  mol.addBond(2, 3, 1);
  mol.addBond(2, 4, 1);

  // Swap the carbon with a hydrogen it is bonded to.
  Array<Index> order(5);
  order[0] = 0;
  order[1] = 2;
  order[2] = 1;
  order[3] = 3;
  order[4] = 4;
  ASSERT_TRUE(mol.reorderAtoms(order));

  // The carbon is at index 1 now, still with four bonds, and each of them is
  // reachable from both ends.
  ASSERT_EQ(static_cast<Index>(4), mol.bondCount());
  EXPECT_EQ(static_cast<size_t>(4), mol.bonds(1).size());
  for (Index b = 0; b < mol.bondCount(); ++b) {
    const RWMolecule::BondType bond = mol.bond(b);
    EXPECT_TRUE(mol.bond(bond.atom1(), bond.atom2()).isValid())
      << "bond " << b << " cannot be found from its own atoms";
  }

  // Removing the multiply-bonded atom is what used to take it down.
  EXPECT_TRUE(mol.removeAtom(1));
  EXPECT_EQ(static_cast<Index>(4), mol.atomCount());
  EXPECT_EQ(static_cast<Index>(0), mol.bondCount());
}

namespace {
// A removed bond's unique id is tombstoned with MaxIndex and never recycled,
// so m_bondUniqueIds is allowed to be longer than the bond list. What must
// hold is that the live slots name the bonds, each exactly once: a unique id
// pointing at a bond index that does not exist is what let an undo command
// swap past the end of the bond list.
void expectUniqueIdsMatchBonds(Molecule& molecule)
{
  const Index bondCount = molecule.bondCount();
  std::vector<int> seen(bondCount, 0);
  Index live = 0;
  const Array<Index>& uids = molecule.bondUniqueIds();
  for (Index uid = 0; uid < static_cast<Index>(uids.size()); ++uid) {
    const Index index = uids[uid];
    if (index == Avogadro::MaxIndex)
      continue;
    ++live;
    ASSERT_LT(index, bondCount)
      << "unique id " << uid << " names bond " << index << ", which is not one";
    EXPECT_EQ(0, seen[index]++) << "bond " << index << " has two unique ids";
  }
  EXPECT_EQ(bondCount, live);
}
} // namespace

TEST(RWMoleculeTest, addBondOnAnAlreadyBondedPair)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(6);

  const RWMolecule::BondType first = mol.addBond(0, 1, 1);
  ASSERT_TRUE(first.isValid());

  // Core::Molecule::addBond() never gives a bonded pair a second bond: it
  // updates the order and returns the bond that is already there. The unique
  // id bookkeeping has to agree, or m_bondUniqueIds grows past the bond list
  // and findBondUniqueId() starts answering with an id whose bond does not
  // exist -- which is how an undo command came to swap a bond index that was
  // one past the end.
  const RWMolecule::BondType again = mol.addBond(0, 1, 2);
  EXPECT_TRUE(again.isValid());
  EXPECT_EQ(first.index(), again.index());
  EXPECT_EQ(static_cast<Index>(1), mol.bondCount());
  EXPECT_EQ(2, mol.bondOrder(first.index()));
  expectUniqueIdsMatchBonds(m);

  // The order change is undoable like any other, and undoing it does not
  // take the bond with it.
  mol.undoStack().undo();
  EXPECT_EQ(static_cast<Index>(1), mol.bondCount());
  EXPECT_EQ(1, mol.bondOrder(first.index()));

  // Undoing the original add does remove it, and redo brings it back once.
  mol.undoStack().undo();
  EXPECT_EQ(static_cast<Index>(0), mol.bondCount());
  mol.undoStack().redo();
  EXPECT_EQ(static_cast<Index>(1), mol.bondCount());
  expectUniqueIdsMatchBonds(m);
}

TEST(RWMoleculeTest, removeBondUndoAfterADuplicateAdd)
{
  // The sequence the fuzz target found: a duplicate bond used to leave a
  // unique id pointing at a bond index that did not exist, and the next
  // bond removal recorded that id. Undoing it then found the id taken,
  // skipped the re-add, and swapped bondCount() - 1 anyway.
  Molecule m;
  RWMolecule mol(m);
  for (int i = 0; i < 4; ++i)
    mol.addAtom(6);

  mol.addBond(0, 1, 1);
  mol.addBond(0, 1, 1); // already bonded
  mol.addBond(2, 3, 1);
  ASSERT_EQ(static_cast<Index>(2), mol.bondCount());

  ASSERT_TRUE(mol.removeBond(1));
  EXPECT_EQ(static_cast<Index>(1), mol.bondCount());

  mol.undoStack().undo();
  ASSERT_EQ(static_cast<Index>(2), mol.bondCount());

  // Both bonds are back where they were, and reachable from their atoms.
  EXPECT_TRUE(mol.bond(0, 1).isValid());
  EXPECT_TRUE(mol.bond(2, 3).isValid());
  expectUniqueIdsMatchBonds(m);
}

TEST(RWMoleculeTest, addAtomWithoutPositions)
{
  // RWMolecule::addAtom(num, false) routes to the unique-id overload with an
  // id one past the end, which used to be refused outright: no atom was added
  // while an AtomType was handed back saying one had been, and the undo that
  // followed removed whatever atom later took that index.
  Molecule m;
  RWMolecule mol(m);

  const RWMolecule::AtomType first = mol.addAtom(6, false);
  EXPECT_TRUE(first.isValid());
  ASSERT_EQ(static_cast<Index>(1), mol.atomCount());
  EXPECT_EQ(6, mol.atomicNumber(0));

  const RWMolecule::AtomType second = mol.addAtom(8, false);
  EXPECT_TRUE(second.isValid());
  ASSERT_EQ(static_cast<Index>(2), mol.atomCount());
  EXPECT_EQ(8, mol.atomicNumber(1));

  // Undo takes the atoms it added, and only those.
  mol.undoStack().undo();
  ASSERT_EQ(static_cast<Index>(1), mol.atomCount());
  EXPECT_EQ(6, mol.atomicNumber(0));
  mol.undoStack().redo();
  ASSERT_EQ(static_cast<Index>(2), mol.atomCount());
  EXPECT_EQ(8, mol.atomicNumber(1));
}

TEST(RWMoleculeTest, setLayerToALayerThatDoesNotExistYet)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(8);
  ASSERT_EQ(static_cast<size_t>(1), m.layer().layerCount());

  // Moving an atom to a layer that has not been created yet creates it.
  EXPECT_TRUE(mol.setLayer(1, 2));
  EXPECT_EQ(static_cast<size_t>(2), m.layer().getLayerID(1));
  EXPECT_EQ(static_cast<size_t>(3), m.layer().layerCount());
  EXPECT_EQ(static_cast<size_t>(0), m.layer().getLayerID(0));

  // Undo puts the atom back in its old layer. The layers it grew stay --
  // nothing else keyed to them was created either, and an empty layer is
  // what Add Layer leaves behind too.
  mol.undoStack().undo();
  EXPECT_EQ(static_cast<size_t>(0), m.layer().getLayerID(1));
  mol.undoStack().redo();
  EXPECT_EQ(static_cast<size_t>(2), m.layer().getLayerID(1));
}

TEST(RWMoleculeTest, undoRedoKeepsTheBondUniqueId)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(6);
  ASSERT_TRUE(mol.addBond(0, 1, 1).isValid());

  const Index uid = m.bondUniqueId(m.bond(0, 1));
  ASSERT_NE(Avogadro::MaxIndex, uid);
  ASSERT_EQ(static_cast<size_t>(1), m.bondUniqueIds().size());

  // A bond that comes back from an undo has to come back as the same bond.
  // PersistentBond and everything else holding onto one resolves through
  // bondByUniqueId(), so the tombstoned slot has to be reclaimed rather than
  // a fresh id appended -- which also kept m_bondUniqueIds growing by one on
  // every undo/redo cycle.
  for (int cycle = 0; cycle < 3; ++cycle) {
    mol.undoStack().undo();
    ASSERT_EQ(static_cast<Index>(0), mol.bondCount());
    EXPECT_FALSE(m.bondByUniqueId(uid).isValid());

    mol.undoStack().redo();
    ASSERT_EQ(static_cast<Index>(1), mol.bondCount());
    EXPECT_TRUE(m.bondByUniqueId(uid).isValid()) << "cycle " << cycle;
    EXPECT_EQ(uid, m.bondUniqueId(m.bond(0, 1))) << "cycle " << cycle;
    EXPECT_EQ(static_cast<size_t>(1), m.bondUniqueIds().size())
      << "cycle " << cycle;
    expectUniqueIdsMatchBonds(m);
  }
}

// ---------------------------------------------------------------------------
// Snapshot helper: everything a user (or anything holding an atom index or
// unique id across an edit) can observe about a molecule. Bonds are recorded
// by their atoms' unique ids rather than by bond index, since removeBond()
// and reorderAtoms() are both free to renumber bonds and atoms.
// ---------------------------------------------------------------------------

namespace {

struct AtomSnapshot
{
  unsigned char atomicNumber = 0;
  Vector3 position = Vector3::Zero();
  bool selected = false;
  std::string label;
  signed char formalCharge = 0;
  size_t layerId = 0;
  Index uniqueId = Avogadro::MaxIndex;
};

struct MoleculeSnapshot
{
  Index atomCount = 0;
  std::vector<AtomSnapshot> atoms;
  // (loUid, hiUid, order) per bond, sorted, so bond index order never matters.
  std::vector<std::tuple<Index, Index, unsigned char>> bonds;
  size_t maxLayer = 0;
  size_t activeLayer = 0;
  size_t coordinateSetCount = 0;
};

MoleculeSnapshot snapshot(RWMolecule& mol)
{
  MoleculeSnapshot s;
  s.atomCount = mol.atomCount();
  s.atoms.reserve(s.atomCount);
  for (Index i = 0; i < s.atomCount; ++i) {
    AtomSnapshot a;
    a.atomicNumber = mol.atomicNumber(i);
    a.position = mol.atomPosition3d(i);
    a.selected = mol.atomSelected(i);
    a.label = mol.atomLabel(i);
    a.formalCharge = mol.formalCharge(i);
    a.layerId = mol.layer(i);
    a.uniqueId = mol.atomUniqueId(i);
    // A unique id is only useful as a handle if it resolves back to the
    // atom it names -- check the round trip every time a snapshot is taken.
    EXPECT_TRUE(mol.atomByUniqueId(a.uniqueId).isValid())
      << "atom " << i << " unique id " << a.uniqueId << " does not resolve";
    EXPECT_EQ(i, mol.atomByUniqueId(a.uniqueId).index())
      << "atom " << i << " unique id " << a.uniqueId << " resolves elsewhere";
    s.atoms.push_back(a);
  }

  for (Index b = 0; b < mol.bondCount(); ++b) {
    std::pair<Index, Index> pair = mol.bondPair(b);
    Index uid1 = mol.atomUniqueId(pair.first);
    Index uid2 = mol.atomUniqueId(pair.second);
    if (uid1 > uid2)
      std::swap(uid1, uid2);
    s.bonds.emplace_back(uid1, uid2, mol.bondOrder(b));
  }
  std::sort(s.bonds.begin(), s.bonds.end());

  s.maxLayer = mol.molecule().layer().maxLayer();
  s.activeLayer = mol.molecule().layer().activeLayer();
  s.coordinateSetCount = mol.molecule().coordinate3dCount();
  return s;
}

::testing::AssertionResult sameMoleculeState(const char* lhsExpr,
                                             const char* rhsExpr,
                                             const MoleculeSnapshot& lhs,
                                             const MoleculeSnapshot& rhs)
{
  if (lhs.atomCount != rhs.atomCount) {
    return ::testing::AssertionFailure()
           << lhsExpr << " has " << lhs.atomCount << " atoms, " << rhsExpr
           << " has " << rhs.atomCount;
  }
  for (Index i = 0; i < lhs.atomCount; ++i) {
    const AtomSnapshot& a = lhs.atoms[i];
    const AtomSnapshot& b = rhs.atoms[i];
    if (a.atomicNumber != b.atomicNumber)
      return ::testing::AssertionFailure()
             << "atom " << i
             << " atomic number: " << static_cast<int>(a.atomicNumber) << " ("
             << lhsExpr << ") vs " << static_cast<int>(b.atomicNumber) << " ("
             << rhsExpr << ")";
    if (a.position != b.position)
      return ::testing::AssertionFailure()
             << "atom " << i << " position differs";
    if (a.selected != b.selected)
      return ::testing::AssertionFailure()
             << "atom " << i << " selected: " << a.selected << " vs "
             << b.selected;
    if (a.label != b.label)
      return ::testing::AssertionFailure()
             << "atom " << i << " label: '" << a.label << "' vs '" << b.label
             << "'";
    if (a.formalCharge != b.formalCharge)
      return ::testing::AssertionFailure()
             << "atom " << i
             << " formal charge: " << static_cast<int>(a.formalCharge) << " vs "
             << static_cast<int>(b.formalCharge);
    if (a.layerId != b.layerId)
      return ::testing::AssertionFailure()
             << "atom " << i << " layer: " << a.layerId << " vs " << b.layerId;
    if (a.uniqueId != b.uniqueId)
      return ::testing::AssertionFailure()
             << "atom " << i << " unique id: " << a.uniqueId << " vs "
             << b.uniqueId;
  }
  if (lhs.bonds != rhs.bonds) {
    return ::testing::AssertionFailure()
           << lhsExpr << " has " << lhs.bonds.size() << " bonds, " << rhsExpr
           << " has " << rhs.bonds.size()
           << " (or the (atom uid, atom uid, order) "
           << "triples differ)";
  }
  if (lhs.maxLayer != rhs.maxLayer)
    return ::testing::AssertionFailure()
           << "maxLayer: " << lhs.maxLayer << " vs " << rhs.maxLayer;
  if (lhs.activeLayer != rhs.activeLayer)
    return ::testing::AssertionFailure()
           << "activeLayer: " << lhs.activeLayer << " vs " << rhs.activeLayer;
  if (lhs.coordinateSetCount != rhs.coordinateSetCount)
    return ::testing::AssertionFailure()
           << "coordinate set count: " << lhs.coordinateSetCount << " vs "
           << rhs.coordinateSetCount;
  return ::testing::AssertionSuccess();
}

#define EXPECT_SAME_STATE(a, b) EXPECT_PRED_FORMAT2(sameMoleculeState, a, b)

} // namespace

TEST(RWMoleculeTest, snapshotRoundTripHandWrittenSequence)
{
  Molecule m;
  RWMolecule mol(m);

  mol.addAtom(6);
  mol.addAtom(6);
  mol.addAtom(8);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 2);
  mol.setAtomLabel(2, "carbonyl O");
  mol.setAtomSelected(1, true);
  // Create a second layer up front: layer creation itself is not part of what
  // undo reverts (setLayerToALayerThatDoesNotExistYet above documents this),
  // so it has to already exist before `start` is captured for setLayer()
  // below to round-trip cleanly.
  mol.setLayer(0, 1);
  mol.setLayer(0, 0);

  const MoleculeSnapshot start = snapshot(mol);
  const int startIndex = mol.undoStack().index();

  // One of each kind of edit the brief asks for, in one pass: addAtom,
  // addBond, setAtomPosition3d, setAtomicNumber, setBondOrder,
  // setAtomSelected, setLayer, removeBond, removeAtom and reorderAtoms
  // (the closest thing RWMolecule has to a public "swap" primitive).
  mol.addAtom(1);
  mol.addBond(0, 3, 1);
  mol.setAtomPosition3d(3, Vector3(Real(1), Real(2), Real(3)));
  mol.setAtomicNumber(2, 7);
  mol.setBondOrder(1, 1);
  mol.setAtomSelected(0, true);
  mol.setAtomSelected(1, false);
  mol.setLayer(3, 1); // layer 1 already exists, so this fully round-trips
  ASSERT_TRUE(mol.removeBond(0, 3));
  ASSERT_TRUE(mol.removeAtom(3));
  Array<Index> order(3);
  order[0] = 2;
  order[1] = 0;
  order[2] = 1;
  ASSERT_TRUE(mol.reorderAtoms(order));

  const MoleculeSnapshot end = snapshot(mol);
  const int endIndex = mol.undoStack().index();
  ASSERT_GT(endIndex, startIndex);

  while (mol.undoStack().index() > startIndex)
    mol.undoStack().undo();
  EXPECT_SAME_STATE(start, snapshot(mol));

  while (mol.undoStack().index() < endIndex)
    mol.undoStack().redo();
  EXPECT_SAME_STATE(end, snapshot(mol));
}

// RemoveAtomCommand (rwmolecule_undo.h) only ever stashes the removed atom's
// atomic number, position and bonds before calling Molecule::removeAtom() --
// see its constructor and redo(). Nothing captures the label or selection
// state, so undo() re-adds a bare atom (via addAtom(number, position, uid))
// and never restores either.
TEST(RWMoleculeTest, removeAtomWithBondsSelectionAndLabelUndoRedo)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(7);
  mol.addAtom(8);
  mol.addAtom(9);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 2);
  mol.addBond(1, 3, 1);
  mol.setAtomSelected(1, true);
  mol.setAtomLabel(1, "central");
  mol.setFormalCharge(1, -1);

  const MoleculeSnapshot before = snapshot(mol);
  const int beforeIndex = mol.undoStack().index();

  ASSERT_TRUE(mol.removeAtom(1));
  EXPECT_EQ(static_cast<Index>(3), mol.atomCount());
  EXPECT_EQ(static_cast<Index>(0), mol.bondCount());

  const MoleculeSnapshot after = snapshot(mol);

  mol.undoStack().undo();
  EXPECT_EQ(beforeIndex, mol.undoStack().index());
  EXPECT_EQ(static_cast<Index>(4), mol.atomCount());
  EXPECT_EQ(static_cast<Index>(3), mol.bondCount());
  // RemoveAtomCommand restores the atom's captured state, so undo must
  // reproduce the snapshot exactly: label, selection and formal charge
  // included. removeAtomUndoRestoresEveryOptionalPerAtomField below covers
  // the fields the snapshot doesn't.
  EXPECT_SAME_STATE(before, snapshot(mol));

  mol.undoStack().redo();
  EXPECT_SAME_STATE(after, snapshot(mol));
}

// RemoveAtomCommand (rwmolecule_undo.h) must capture every per-atom optional
// value molecule.h exposes -- not just what the snapshot helper above already
// covers (label, selection, formal charge) -- and restore each once the atom
// is back at its index: color, isotope, hybridization, 2D position and
// frozen-atom state too. Calculated results (partial charges, force vectors)
// are not restored: removeAtom() clears them for every atom on purpose, since
// they describe a molecule that no longer exists once an atom is gone.
TEST(RWMoleculeTest, removeAtomUndoRestoresEveryOptionalPerAtomField)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6); // atom 0: kept, never given any of these values
  mol.addAtom(7); // atom 1: removed and restored

  mol.setAtomSelected(1, true);
  mol.setAtomLabel(1, "central");
  mol.setFormalCharge(1, -1);
  m.setColor(1, Avogadro::Vector3ub(10, 20, 30));
  m.setIsotope(1, 15);
  m.setHybridization(1, Avogadro::Core::SP3);
  m.setAtomPosition2d(1, Avogadro::Vector2(Real(4), Real(5)));
  m.setForceVector(1, Vector3(Real(1), Real(2), Real(3)));
  m.setFrozenAtomAxis(1, 0, true);
  m.setFrozenAtomAxis(1, 2, true);
  // Axis 1 is deliberately left unfrozen, so a restore that just copied
  // "frozen" for the whole atom rather than per axis would be caught too.

  ASSERT_TRUE(mol.removeAtom(1));
  mol.undoStack().undo();

  ASSERT_EQ(static_cast<Index>(2), mol.atomCount());
  EXPECT_TRUE(m.atomSelected(1));
  EXPECT_EQ("central", m.atomLabel(1));
  EXPECT_EQ(static_cast<signed char>(-1), m.formalCharge(1));
  EXPECT_EQ(Avogadro::Vector3ub(10, 20, 30), m.color(1));
  EXPECT_EQ(static_cast<unsigned short>(15), m.isotope(1));
  EXPECT_EQ(Avogadro::Core::SP3, m.hybridization(1));
  EXPECT_EQ(Avogadro::Vector2(Real(4), Real(5)), m.atomPosition2d(1));
  // Cleared for every atom by the removal, and not partially restored.
  EXPECT_TRUE(m.forceVectors().empty());
  EXPECT_TRUE(m.frozenAtomAxis(1, 0));
  EXPECT_FALSE(m.frozenAtomAxis(1, 1));
  EXPECT_TRUE(m.frozenAtomAxis(1, 2));

  // Atom 0 never had any of these set either, and restoring atom 1's values
  // must not have manufactured entries for it.
  EXPECT_EQ("", m.atomLabel(0));
  EXPECT_FALSE(m.atomSelected(0));
  EXPECT_EQ(static_cast<signed char>(0), m.formalCharge(0));
  EXPECT_EQ(static_cast<unsigned short>(0), m.isotope(0));
  EXPECT_EQ(Avogadro::Core::HybridizationUnknown, m.hybridization(0));
  EXPECT_EQ(Avogadro::Vector2::Zero(), m.atomPosition2d(0));
  EXPECT_FALSE(m.frozenAtomAxis(0, 0));

  // redo() re-applies the removal (redo() re-captures from the just-restored
  // atom before removing it again), and a second undo() must restore
  // everything again from that fresh capture -- not just the first time.
  mol.undoStack().redo();
  ASSERT_EQ(static_cast<Index>(1), mol.atomCount());
  mol.undoStack().undo();

  ASSERT_EQ(static_cast<Index>(2), mol.atomCount());
  EXPECT_TRUE(m.atomSelected(1));
  EXPECT_EQ("central", m.atomLabel(1));
  EXPECT_EQ(Avogadro::Vector3ub(10, 20, 30), m.color(1));
}

// An atom that never had any of these optional values set must not gain any
// after a remove/undo round trip -- the arrays stay exactly as short (empty,
// here) as they started. RemoveAtomCommand::undo() guards each restore on
// whether the atom actually had the value, since the setters below would
// otherwise grow the whole array to atomCount() on first write, handing
// every other atom an explicit default entry it never had either.
TEST(RWMoleculeTest, removeAtomUndoWithNoOptionalValuesDoesNotGrowArrays)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);

  ASSERT_TRUE(mol.removeAtom(0));
  mol.undoStack().undo();

  ASSERT_EQ(static_cast<Index>(1), mol.atomCount());
  EXPECT_TRUE(m.atomLabels().empty());
  EXPECT_TRUE(m.formalCharges().empty());
  EXPECT_TRUE(m.colors().empty());
  EXPECT_TRUE(m.isotopes().empty());
  EXPECT_TRUE(m.hybridizations().empty());
  EXPECT_TRUE(m.atomPositions2d().empty());
  EXPECT_TRUE(m.forceVectors().empty());
  EXPECT_EQ(static_cast<Eigen::Index>(0), m.frozenAtomMask().rows());
}

TEST(RWMoleculeTest, removeLastAtomUndoRedo)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(7);
  mol.addAtom(8);
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 2);
  mol.setAtomPosition3d(2, Vector3(Real(4), Real(5), Real(6)));

  const MoleculeSnapshot before = snapshot(mol);

  ASSERT_TRUE(mol.removeAtom(2)); // already the last atom: no swap needed
  EXPECT_EQ(static_cast<Index>(2), mol.atomCount());
  EXPECT_EQ(static_cast<Index>(1), mol.bondCount());

  const MoleculeSnapshot after = snapshot(mol);

  mol.undoStack().undo();
  EXPECT_SAME_STATE(before, snapshot(mol));

  mol.undoStack().redo();
  EXPECT_SAME_STATE(after, snapshot(mol));
}

// After undoing the removal of an atom in the middle of the index range, the
// bond graph, bondPairs() and every atom's unique id have to agree with each
// other again -- this is the scenario rwmolecule_unique_id_desync.md and the
// fuzz target (fuzz-rwmolecule.cpp) were written against.
TEST(RWMoleculeTest, consistencyAfterUndoOfMiddleAtomRemoval)
{
  Molecule m;
  RWMolecule mol(m);
  for (int i = 0; i < 5; ++i)
    mol.addAtom(static_cast<unsigned char>(6 + i));
  mol.addBond(0, 1, 1);
  mol.addBond(1, 2, 1);
  mol.addBond(2, 3, 1);
  mol.addBond(3, 4, 1);
  mol.addBond(0, 4, 1);

  const MoleculeSnapshot before = snapshot(mol);

  ASSERT_TRUE(mol.removeAtom(2)); // a middle atom, with two bonds
  mol.undoStack().undo();

  EXPECT_SAME_STATE(before, snapshot(mol));
  expectUniqueIdsMatchBonds(m);

  // Every unique id round-trips to the atom that names it...
  for (Index i = 0; i < mol.atomCount(); ++i)
    EXPECT_EQ(i, mol.atomByUniqueId(mol.atomUniqueId(i)).index())
      << "atom " << i;

  // ...and bondPairs() agrees with the bond graph from both ends.
  const Array<std::pair<Index, Index>>& pairs = mol.bondPairs();
  ASSERT_EQ(mol.bondCount(), static_cast<Index>(pairs.size()));
  for (Index b = 0; b < mol.bondCount(); ++b) {
    EXPECT_TRUE(mol.bond(pairs[b].first, pairs[b].second).isValid())
      << "bond " << b << " not reachable from its own bondPairs() entry";
    EXPECT_TRUE(mol.bond(b).atom1().isValid() && mol.bond(b).atom2().isValid())
      << "bond " << b;
  }
}

// A seeded random walk of ~300 operations, checked at regular checkpoints and
// at the very start and end, jumping around with QUndoStack::setIndex()
// rather than only ever stepping one at a time.
TEST(RWMoleculeTest, randomSequenceUndoRedoRoundTrip)
{
  Molecule m;
  RWMolecule mol(m);

  std::mt19937 rng(20260922u);
  std::uniform_int_distribution<int> opPick(0, 8);
  std::uniform_int_distribution<int> elementPick(1, 30);
  std::uniform_int_distribution<int> orderPick(1, 3);
  std::uniform_int_distribution<int> coordPick(-5, 5);

  std::vector<int> checkpointIndex;
  std::vector<MoleculeSnapshot> checkpointSnapshot;
  auto checkpoint = [&]() {
    // QUndoStack never merges into the command at the clean index, so the
    // next mergeable edit can't change the state recorded here.
    mol.undoStack().setClean();
    checkpointIndex.push_back(mol.undoStack().index());
    checkpointSnapshot.push_back(snapshot(mol));
  };
  checkpoint(); // index 0: the empty molecule

  for (int step = 0; step < 300; ++step) {
    const Index atomCount = mol.atomCount();
    const Index bondCount = mol.bondCount();
    switch (opPick(rng)) {
      case 0:
      case 1: // addAtom is weighted higher so the molecule tends to grow
        mol.addAtom(static_cast<unsigned char>(elementPick(rng)));
        break;
      case 2:
        if (atomCount >= 2) {
          std::uniform_int_distribution<Index> pick(0, atomCount - 1);
          Index a = pick(rng), b = pick(rng);
          if (a != b)
            mol.addBond(a, b, static_cast<unsigned char>(orderPick(rng)));
        }
        break;
      case 3:
        if (atomCount > 0) {
          std::uniform_int_distribution<Index> pick(0, atomCount - 1);
          mol.removeAtom(pick(rng));
        }
        break;
      case 4:
        if (bondCount > 0) {
          std::uniform_int_distribution<Index> pick(0, bondCount - 1);
          mol.removeBond(pick(rng));
        }
        break;
      case 5:
        if (atomCount > 0) {
          std::uniform_int_distribution<Index> pick(0, atomCount - 1);
          mol.setAtomSelected(pick(rng), (rng() & 1) != 0);
        }
        break;
      case 6:
        if (atomCount > 0) {
          std::uniform_int_distribution<Index> pick(0, atomCount - 1);
          mol.setAtomPosition3d(pick(rng), Vector3(Real(coordPick(rng)),
                                                   Real(coordPick(rng)),
                                                   Real(coordPick(rng))));
        }
        break;
      case 7:
        if (bondCount > 0) {
          std::uniform_int_distribution<Index> pick(0, bondCount - 1);
          mol.setBondOrder(pick(rng),
                           static_cast<unsigned char>(orderPick(rng)));
        }
        break;
      case 8:
      default:
        if (atomCount >= 2) {
          Array<Index> order(atomCount);
          for (Index i = 0; i < atomCount; ++i)
            order[i] = i;
          std::shuffle(order.begin(), order.end(), rng);
          mol.reorderAtoms(order);
        }
        break;
    }
    if ((step + 1) % 30 == 0)
      checkpoint();
  }
  checkpoint(); // the final state

  // Jump to a few checkpoints out of sequence: exercises setIndex() picking
  // its own path of undo()/redo() calls, not just single steps.
  const std::vector<size_t> toVisit = { checkpointIndex.size() / 2, 1,
                                        checkpointIndex.size() - 1, 0 };
  for (size_t c : toVisit) {
    mol.undoStack().setIndex(checkpointIndex[c]);
    EXPECT_SAME_STATE(checkpointSnapshot[c], snapshot(mol))
      << "checkpoint " << c;
  }

  // Undo the entire stack one command at a time and land back on the start.
  while (mol.undoStack().canUndo())
    mol.undoStack().undo();
  EXPECT_SAME_STATE(checkpointSnapshot.front(), snapshot(mol));

  // Redo the entire stack and land back on the end.
  while (mol.undoStack().canRedo())
    mol.undoStack().redo();
  EXPECT_SAME_STATE(checkpointSnapshot.back(), snapshot(mol));
}

// ---------------------------------------------------------------------------
// changed() flag semantics. molecule.h documents one explicit rule: the
// Conformer comment says switching the active coordinate set is view-state
// and "should pair with Moved (not Modified)". Everything else below is
// what RWMolecule/Molecule::changed() actually do today, captured with a
// connected lambda rather than QSignalSpy (QSignalSpy wants a
// QCoreApplication; a direct same-thread connection does not).
// ---------------------------------------------------------------------------

namespace {

std::vector<unsigned int> captureChanges(Molecule& m,
                                         const std::function<void()>& action)
{
  std::vector<unsigned int> seen;
  QMetaObject::Connection c =
    QObject::connect(&m, &Molecule::changed,
                     [&seen](unsigned int change) { seen.push_back(change); });
  action();
  QObject::disconnect(c);
  return seen;
}

} // namespace

// rwmolecule.h's doc comments say "Changes are emitted." on addUnitCell(),
// removeUnitCell(), modifyMolecule(), appendMolecule(), editUnitCell() and
// the other whole-molecule operations -- and only on those. addAtom(),
// removeAtom(), addBond(), removeBond(), setAtomicNumber(), setBondOrder()
// and setAtomPosition3d() carry no such note. What they do today: nothing.
// No Molecule::changed signal at all, from the call, from undo(), or from
// redo(). Callers are expected to call emitChanged() themselves once they
// are done (see qtplugins/editor/editor.cpp and
// qtplugins/manipulator/manipulator.cpp, which do exactly that after driving
// RWMolecule). Since nothing is emitted, Modified in particular never
// appears at this layer for any of these calls.
TEST(RWMoleculeTest, changedSignalStructuralEditsEmitNothingByThemselves)
{
  Molecule m;
  RWMolecule mol(m);

  auto changes = captureChanges(m, [&]() {
    mol.addAtom(6);
    mol.addAtom(6);
    mol.addBond(0, 1, 1);
    mol.setAtomicNumber(0, 7);
    mol.setAtomPosition3d(0, Vector3(Real(1), Real(2), Real(3)));
    mol.setBondOrder(0, 2);
    mol.removeBond(0);
    mol.removeAtom(1);
  });
  EXPECT_TRUE(changes.empty());

  // Undo and redo of those same edits are just as silent.
  changes = captureChanges(m, [&]() {
    while (mol.undoStack().canUndo())
      mol.undoStack().undo();
  });
  EXPECT_TRUE(changes.empty());

  changes = captureChanges(m, [&]() {
    while (mol.undoStack().canRedo())
      mol.undoStack().redo();
  });
  EXPECT_TRUE(changes.empty());
}

// molecule.h states the Moved-vs-Modified rule explicitly only for Conformer;
// there is no equivalent sentence for Selection. What holds today is
// stronger than "no Modified": setAtomSelected() does not call emitChanged()
// at all, so undocumented as it is, a selection change alone can never look
// like a document edit to something watching Molecule::changed (relevant to
// avogadroapp #476 -- MainWindow::markMoleculeDirty is connected straight to
// this signal).
TEST(RWMoleculeTest, changedSignalSelectionEmitsNothing)
{
  Molecule m;
  RWMolecule mol(m);
  mol.addAtom(6);
  mol.addAtom(6);

  auto changes = captureChanges(m, [&]() {
    mol.setAtomSelected(0, true);
    mol.setAtomSelected(1, true);
    mol.setAtomSelected(0, false);
  });
  EXPECT_TRUE(changes.empty());

  changes = captureChanges(m, [&]() { mol.undoStack().undo(); });
  EXPECT_TRUE(changes.empty());
}

// reorderAtoms() is the one per-atom/per-bond mutator that does notify
// directly (see the comment on ReorderAtomsCommand in rwmolecule_undo.h):
// undo() and redo() through the stack each emit exactly once, carrying
// Reordered alongside Atoms | Bonds | Modified.
TEST(RWMoleculeTest, changedSignalReorderAtomsUndoRedoEmitOnceWithReorderedFlag)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 3);
  Array<Index> order(3);
  order[0] = 2;
  order[1] = 0;
  order[2] = 1;
  ASSERT_TRUE(mol.reorderAtoms(order));

  const unsigned int expected = Molecule::Atoms | Molecule::Bonds |
                                Molecule::Modified | Molecule::Reordered;

  auto changes = captureChanges(m, [&]() { mol.undoStack().undo(); });
  ASSERT_EQ(static_cast<size_t>(1), changes.size());
  EXPECT_EQ(expected, changes[0]);

  changes = captureChanges(m, [&]() { mol.undoStack().redo(); });
  ASSERT_EQ(static_cast<size_t>(1), changes.size());
  EXPECT_EQ(expected, changes[0]);
}

// reorderAtoms() must not double up on its own command's notification:
// ReorderAtomsCommand::redo() (run synchronously by push()) already emits
// Atoms|Bonds|Modified|Reordered once, so reorderAtoms() itself must not
// emit again afterward.
TEST(RWMoleculeTest, changedSignalReorderAtomsInitialCallEmitsOnce)
{
  Molecule m;
  RWMolecule mol(m);
  buildDistinctAtoms(mol, 3);

  Array<Index> order(3);
  order[0] = 2;
  order[1] = 0;
  order[2] = 1;

  auto changes =
    captureChanges(m, [&]() { ASSERT_TRUE(mol.reorderAtoms(order)); });

  const unsigned int expected = Molecule::Atoms | Molecule::Bonds |
                                Molecule::Modified | Molecule::Reordered;
  ASSERT_EQ(static_cast<size_t>(1), changes.size());
  EXPECT_EQ(expected, changes[0]);
}

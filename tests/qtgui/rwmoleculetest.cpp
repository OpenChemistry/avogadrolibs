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

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <algorithm>
#include <utility>

using Avogadro::Core::Array;
using Avogadro::QtGui::RWMolecule;
using Avogadro::QtGui::Molecule;
using Avogadro::Index;
using Avogadro::Real;
using Avogadro::Vector3;

// TODO move this to an algorithms header
#include <avogadro/core/elements.h>
#include <map>
#include <sstream>
#include <string>
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
  EXPECT_EQ(std::string("CHBNO"), formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ(std::string("CHBN"), formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ(std::string("CHB"), formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(2, mol.atomCount());
  EXPECT_EQ(std::string("HB"), formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(1, mol.atomCount());
  EXPECT_EQ(std::string("H"), formula(mol));
  mol.undoStack().undo();
  EXPECT_EQ(0, mol.atomCount());

  EXPECT_FALSE(mol.undoStack().canUndo());

  mol.undoStack().redo();
  EXPECT_EQ(1, mol.atomCount());
  EXPECT_EQ(std::string("H"), formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(2, mol.atomCount());
  EXPECT_EQ(std::string("HB"), formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ(std::string("CHB"), formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(4, mol.atomCount());
  EXPECT_EQ(std::string("CHBN"), formula(mol));
  mol.undoStack().redo();
  EXPECT_EQ(5, mol.atomCount());
  EXPECT_EQ(std::string("CHBNO"), formula(mol));

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
  ASSERT_EQ(std::string("HHeLiBeB"), formula(mol));

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
  EXPECT_EQ(std::string("HHeBeB"), formula(mol));
  EXPECT_FALSE(mol.atomByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(1).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(2).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(4).isValid());
  EXPECT_FALSE(mol.bondByUniqueId(6).isValid());

  EXPECT_TRUE(mol.removeAtom(0));
  EXPECT_EQ(3, mol.atomCount());
  EXPECT_EQ(3, mol.bondCount());
  EXPECT_EQ(std::string("HeBeB"), formula(mol));
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
  EXPECT_EQ(std::string("HHeBeB"), formula(mol));
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
  ASSERT_EQ(std::string("HHeLiBeB"), formula(mol));

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
  ASSERT_EQ(std::string("HHeLiBeB"), formula(mol));

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
  ASSERT_EQ(std::string("HHeLiBeB"), formula(mol));

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
                         rep.begin()));

  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomicNumbers().begin(), mol.atomicNumbers().end(),
                         orig.begin()));
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
                         mol.atomPositions3d().end(), pos.begin()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), oldPositions.begin()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin()));
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
                         mol.atomPositions3d().end(), pos.begin()));
  EXPECT_EQ(1, mol.undoStack().count());
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), oldPositions.begin()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(mol.atomPositions3d().begin(),
                         mol.atomPositions3d().end(), pos.begin()));
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
  EXPECT_TRUE(
    std::equal(pos.begin(), pos.end(), mol.atomPositions3d().begin()));
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
  EXPECT_TRUE(std::equal(pairs.begin(), pairs.end(), mol.bondPairs().begin()));
  EXPECT_TRUE(std::equal(ords.begin(), ords.end(), mol.bondOrders().begin()));
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
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondOrders().begin()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(old.begin(), old.end(), mol.bondOrders().begin()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondOrders().begin()));
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

namespace {
inline std::pair<Index, Index> makeBondPair(Index a, Index b)
{
  return a < b ? std::make_pair(a, b) : std::make_pair(b, a);
}
} // end anon namespace

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
  ASSERT_EQ(makeBondPair(0, 1), mol.bondPair(0));
  ASSERT_EQ(makeBondPair(1, 2), mol.bondPair(1));
  ASSERT_EQ(makeBondPair(2, 3), mol.bondPair(2));
  mol.undoStack().clear();

  typedef std::pair<Index, Index> BondPair;
  Array<BondPair> old(mol.bondPairs());
  Array<BondPair> rep(old);
  for (Array<BondPair>::iterator it = rep.begin(), itEnd = rep.end();
       it != itEnd; ++it) {
    ++it->second;
  }

  mol.setBondPairs(rep);
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondPairs().begin()));
  mol.undoStack().undo();
  EXPECT_TRUE(std::equal(old.begin(), old.end(), mol.bondPairs().begin()));
  mol.undoStack().redo();
  EXPECT_TRUE(std::equal(rep.begin(), rep.end(), mol.bondPairs().begin()));
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
  ASSERT_EQ(makeBondPair(0, 1), mol.bondPair(0));
  ASSERT_EQ(makeBondPair(1, 2), mol.bondPair(1));
  ASSERT_EQ(makeBondPair(2, 3), mol.bondPair(2));
  mol.undoStack().clear();

  mol.setBondPair(0, makeBondPair(0, 2));
  mol.setBondPair(2, makeBondPair(2, 4));

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

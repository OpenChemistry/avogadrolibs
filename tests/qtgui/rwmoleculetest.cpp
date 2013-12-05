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

#include <avogadro/qtgui/rwmolecule.h>

using Avogadro::Core::Array;
using Avogadro::QtGui::RWMolecule;
using Avogadro::Index;
using Avogadro::Real;
using Avogadro::Vector3;

// TODO move this to an algorithms header
#include <map>
#include <sstream>
#include <string>
#include <avogadro/core/elements.h>
template <class MoleculeType>
std::string formula(const MoleculeType &mol)
{
  // Adapted from chemkit:
  // A map of atomic symbols to their quantity.
  std::map<unsigned char, size_t> composition;
  for (Array<unsigned char>::const_iterator it = mol.atomicNumbers().begin(),
       itEnd = mol.atomicNumbers().end(); it != itEnd; ++it) {
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
  RWMolecule mol;

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
  RWMolecule mol;
  typedef RWMolecule::AtomType Atom;

  Atom a0 = mol.addAtom(1); // H
  Atom a1 = mol.addAtom(2); // He
  Atom a2 = mol.addAtom(3); // Li
  Atom a3 = mol.addAtom(4); // Be
  Atom a4 = mol.addAtom(5); // B

  const Vector3 pos(Real(1), Real(2), Real(3));
  mol.setPosition3d(0, pos);

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
    EXPECT_EQ(Real(0), mol.position3d(i).x()) << " for atom index " << i;
    EXPECT_EQ(Real(0), mol.position3d(i).y()) << " for atom index " << i;
    EXPECT_EQ(Real(0), mol.position3d(i).z()) << " for atom index " << i;
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

  EXPECT_EQ(pos.x(), mol.position3d(0).x());
  EXPECT_EQ(pos.y(), mol.position3d(0).y());
  EXPECT_EQ(pos.z(), mol.position3d(0).z());

  mol.undoStack().undo();

  ASSERT_EQ(5, mol.atomCount());
  ASSERT_EQ(10, mol.bondCount());
  ASSERT_EQ(std::string("HHeLiBeB"), formula(mol));

  for (Index i = 0; i < mol.atomCount(); ++i) {
    EXPECT_EQ(static_cast<unsigned char>(i + 1), mol.atomicNumber(i));
    EXPECT_EQ(i, mol.atomUniqueId(i));
  }

#define VALIDATE_BOND(ind, atom1, atom2, order, uid) \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind)); \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind)); \
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
  RWMolecule mol;
  typedef RWMolecule::AtomType Atom;

  Atom a0 = mol.addAtom(1); // H
  Atom a1 = mol.addAtom(2); // He
  Atom a2 = mol.addAtom(3); // Li
  Atom a3 = mol.addAtom(4); // Be
  Atom a4 = mol.addAtom(5); // B

  const Vector3 pos(Real(1), Real(2), Real(3));
  mol.setPosition3d(0, pos);

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

#define VALIDATE_BOND(ind, atom1, atom2, order, uid) \
  EXPECT_EQ(std::make_pair(Index(atom1), Index(atom2)), mol.bondPair(ind)); \
  EXPECT_EQ(static_cast<unsigned char>(order), mol.bondOrder(ind)); \
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

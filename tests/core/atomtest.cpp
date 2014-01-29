/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

using Avogadro::Core::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Vector2;
using Avogadro::Vector3;

TEST(AtomTest, setAtomicNumber)
{
  Molecule molecule;
  Atom atom = molecule.addAtom(1);
  EXPECT_TRUE(atom.isValid());
  EXPECT_EQ(atom.atomicNumber(), 1);

  // change the atom's atomic number
  atom.setAtomicNumber(6);
  EXPECT_EQ(atom.atomicNumber(), 6);
}

TEST(AtomTest, setAtomPosition2d)
{
  Molecule molecule;
  Atom atom = molecule.addAtom(1);

  // Should return a zero vector if the position has not been set.
  EXPECT_EQ(atom.position2d().x(), 0.0);
  EXPECT_EQ(atom.position2d().y(), 0.0);

  // Now set the position and verify it was stored correctly.
  atom.setPosition2d(Vector2(0.5, 1.0));
  EXPECT_EQ(atom.position2d().x(), 0.5);
  EXPECT_EQ(atom.position2d().y(), 1.0);

  // Try with a second atom, confirm no cross over with the first too.
  Atom atom2 = molecule.addAtom(6);
  atom2.setPosition2d(Vector2(0.42, 3.14));
  EXPECT_EQ(atom.position2d().x(), 0.5);
  EXPECT_EQ(atom.position2d().y(), 1.0);
  EXPECT_EQ(atom2.position2d().x(), 0.42);
  EXPECT_EQ(atom2.position2d().y(), 3.14);
}

TEST(AtomTest, setAtomPosition3d)
{
  Molecule molecule;
  Atom atom = molecule.addAtom(1);

  // Should return a zero vector if the position has not been set.
  EXPECT_EQ(atom.position3d().x(), 0.0);
  EXPECT_EQ(atom.position3d().y(), 0.0);
  EXPECT_EQ(atom.position3d().z(), 0.0);

  // Now set the position and verify it was stored correctly.
  atom.setPosition3d(Vector3(0.5, 1.0, 1.5));
  EXPECT_EQ(atom.position3d().x(), 0.5);
  EXPECT_EQ(atom.position3d().y(), 1.0);
  EXPECT_EQ(atom.position3d().z(), 1.5);

  // Try with a second atom, confirm no cross over with the first too.
  Atom atom2 = molecule.addAtom(6);
  atom2.setPosition3d(Vector3(0.42, 3.14, 6.66));
  EXPECT_EQ(atom.position3d().x(), 0.5);
  EXPECT_EQ(atom.position3d().y(), 1.0);
  EXPECT_EQ(atom.position3d().z(), 1.5);
  EXPECT_EQ(atom2.position3d().x(), 0.42);
  EXPECT_EQ(atom2.position3d().y(), 3.14);
  EXPECT_EQ(atom2.position3d().z(), 6.66);
}

TEST(AtomTest, operators)
{
  Molecule molecule;
  Atom atom1 = molecule.addAtom(1);
  Atom atom2 = molecule.addAtom(2);
  EXPECT_TRUE(atom1 == molecule.atom(0));
  EXPECT_FALSE(atom1 != molecule.atom(0));
  EXPECT_TRUE(atom1 != molecule.atom(1));
  EXPECT_FALSE(atom1 == molecule.atom(1));
  EXPECT_TRUE(atom1 != atom2);
}

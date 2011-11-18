/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include <atom.h>
#include <molecule.h>

TEST(AtomTest, setAtomicNumber)
{
  MolCore::Molecule molecule;
  MolCore::Atom atom = molecule.addAtom(1);
  EXPECT_TRUE(atom.isValid());
  EXPECT_EQ(atom.atomicNumber(), 1);

  // change the atom's atomic number
  atom.setAtomicNumber(6);
  EXPECT_EQ(atom.atomicNumber(), 6);
}

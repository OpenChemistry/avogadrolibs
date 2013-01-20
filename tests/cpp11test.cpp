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

#include <avogadro/core/memory_p.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/mutex_p.h>

using Avogadro::Core::Molecule;

TEST(CPP11Test, unique_ptr)
{
  AVO_UNIQUE_PTR<Molecule> molecule(new Molecule);
  EXPECT_EQ(molecule->size(), static_cast<size_t>(0));
}

TEST(CPP11Test, shared_ptr)
{
  Avogadro::Core::shared_ptr<Molecule> molecule(new Molecule);
  EXPECT_EQ(molecule->size(), static_cast<size_t>(0));
}

TEST(CPP11Test, weak_ptr)
{
  Avogadro::Core::shared_ptr<Molecule> molecule(new Molecule);
  Avogadro::Core::weak_ptr<Molecule> weakMolecule(molecule);

  EXPECT_EQ(molecule->size(), static_cast<size_t>(0));
  molecule->addAtom(5);
  EXPECT_EQ(molecule->size(), static_cast<size_t>(1));

  Avogadro::Core::shared_ptr<Molecule> sharedMolecule = weakMolecule.lock();
  EXPECT_EQ(sharedMolecule->size(), static_cast<size_t>(1));
}

TEST(CPP11Test, mutex)
{
  Avogadro::Core::mutex mutex;

  mutex.lock();
  int array[15];
  array[4] = 1;
  mutex.unlock();

  EXPECT_EQ(array[4], 1);
}

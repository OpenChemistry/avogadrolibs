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

#include <avogadro/stl/memory_p.h>
#include <avogadro/stl/mutex_p.h>
#include <avogadro/core/molecule.h>

using Avogadro::Core::Molecule;

TEST(CPP11Test, unique_ptr)
{
  AVO_UNIQUE_PTR<Molecule> molecule(new Molecule);
  EXPECT_EQ(molecule->atomCount(), static_cast<size_t>(0));
}

TEST(CPP11Test, shared_ptr)
{
  Avogadro::Stl::shared_ptr<Molecule> molecule(new Molecule);
  EXPECT_EQ(molecule->atomCount(), static_cast<size_t>(0));
}

TEST(CPP11Test, weak_ptr)
{
  Avogadro::Stl::shared_ptr<Molecule> molecule(new Molecule);
  Avogadro::Stl::weak_ptr<Molecule> weakMolecule(molecule);

  EXPECT_EQ(molecule->atomCount(), static_cast<size_t>(0));
  molecule->addAtom(5);
  EXPECT_EQ(molecule->atomCount(), static_cast<size_t>(1));

  Avogadro::Stl::shared_ptr<Molecule> sharedMolecule = weakMolecule.lock();
  EXPECT_EQ(sharedMolecule->atomCount(), static_cast<size_t>(1));
}

TEST(CPP11Test, mutex)
{
  Avogadro::Stl::mutex mutex;

  mutex.lock();
  int array[15];
  array[4] = 1;
  mutex.unlock();

  EXPECT_EQ(array[4], 1);
}

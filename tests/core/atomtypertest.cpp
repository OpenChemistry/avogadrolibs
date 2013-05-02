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
#include <avogadro/core/atom.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/nameatomtyper.h>
#include <avogadro/core/symbolatomtyper.h>

using namespace Avogadro::Core;

TEST(AtomTyper, nameAtomTyper)
{
  Molecule molecule;
  Array<std::string> ref;

  for (unsigned char i = 0; i < Elements::elementCount(); ++i) {
    molecule.addAtom(i);
    ref.push_back(Elements::name(i));
  }

  NameAtomTyper typer(&molecule);
  typer.run();
  Array<std::string> output(typer.types());

  ASSERT_EQ(ref.size(), output.size());
  for (size_t i = 0; i < ref.size(); ++i) {
    EXPECT_EQ(ref[i], output[i]) << "Mismatch at index " << i;
  }
}

TEST(AtomTyper, symbolAtomTyper)
{
  Molecule molecule;
  Array<std::string> ref;

  for (unsigned char i = 0; i < Elements::elementCount(); ++i) {
    molecule.addAtom(i);
    ref.push_back(Elements::symbol(i));
  }

  SymbolAtomTyper typer(&molecule);
  typer.run();
  Array<std::string> output(typer.types());

  ASSERT_EQ(ref.size(), output.size());
  for (size_t i = 0; i < ref.size(); ++i) {
    EXPECT_EQ(ref[i], output[i]) << "Mismatch at index " << i;
  }
}

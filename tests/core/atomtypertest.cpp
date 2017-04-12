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

TEST(AtomTyper, singleAtomTyping)
{
  Molecule molecule;
  Array<double> ref;

  for (unsigned char i = 0; i < Elements::elementCount(); ++i) {
    molecule.addAtom(i);
    ref.push_back(Elements::mass(i));
  }

  class MassTyper : public AtomTyper<double>
  {
  public:
    MassTyper() : AtomTyper<double>(nullptr) {}
    Array<double>& typesRef() { return m_types; }
  protected:
    double type(const Atom& atom)
    {
      return Elements::mass(atom.atomicNumber());
    }
  } typer;

  typer.setMolecule(&molecule);

  // Check that the single atom typing method works as expected
  for (Avogadro::Index i = 0; i < molecule.atomCount(); ++i) {
    EXPECT_EQ(ref[i], typer.atomType(molecule.atom(i)))
      << "run(Atom): Mismatch at index " << i;
  }

  // Verify that we haven't populated the internal array
  EXPECT_TRUE(typer.types().empty());

  // Fill the internal array.
  typer.run();
  Array<double> output(typer.types());

  // Verify the internal array
  ASSERT_EQ(ref.size(), output.size());
  for (size_t i = 0; i < ref.size(); ++i)
    EXPECT_EQ(ref[i], output[i]) << "run(): Mismatch at index " << i;

  // Change a type and verify that we get the cached result from run(Atom).
  const double testVal = -192.34;
  typer.typesRef()[4] = testVal;
  EXPECT_EQ(testVal, typer.atomType(molecule.atom(4)))
    << "Failed getting cached result.";
}

TEST(AtomTyper, resetOnMoleculeChange)
{
  Molecule molecule1;
  Molecule molecule2;

  molecule1.addAtom(1);
  molecule2.addAtom(1);

  NameAtomTyper typer(&molecule1);
  typer.run();
  EXPECT_EQ(1, typer.types().size());

  typer.setMolecule(&molecule2);
  EXPECT_EQ(0, typer.types().size());
}

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
  for (size_t i = 0; i < ref.size(); ++i)
    EXPECT_EQ(ref[i], output[i]) << "Mismatch at index " << i;
}

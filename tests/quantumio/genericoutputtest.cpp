/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

#include <avogadro/quantumio/genericoutput.h>
#include <avogadro/quantumio/orca.h>

#include <cstdio>
#include <fstream>
#include <string>

using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::GenericOutput;
using Avogadro::QuantumIO::ORCAOutput;

namespace {

// The reader picks its delegate from the file name's extension, so the
// fixtures have to be real files with real extensions rather than strings.
class TemporaryFile
{
public:
  TemporaryFile(const std::string& name, const std::string& contents)
    : m_name(name)
  {
    std::ofstream file(m_name.c_str());
    file << contents;
  }

  ~TemporaryFile() { std::remove(m_name.c_str()); }

  const std::string& name() const { return m_name; }

private:
  std::string m_name;
};

bool contains(const std::string& haystack, const std::string& needle)
{
  return haystack.find(needle) != std::string::npos;
}

} // namespace

// A file nothing recognizes used to fail with one sentence that named neither
// the file, the readers that were tried, nor the ones that were missing, which
// left "cannot open Gaussian output" bug reports with nothing to go on.
TEST(GenericOutputTest, unrecognizedOutputSaysWhatWasTried)
{
  TemporaryFile fixture("genericoutput-unrecognized.log",
                        "Entering Link 1\nsome program we do not know\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));

  const std::string error = reader.error();
  // The built-in signatures that were checked...
  EXPECT_TRUE(contains(error, "GAMESS-US"));
  EXPECT_TRUE(contains(error, "NWChem"));
  EXPECT_TRUE(contains(error, "ORCA"));
  // ...and the fallbacks that were not available.
  EXPECT_TRUE(contains(error, "cclib"));
  EXPECT_TRUE(contains(error, "Open Babel"));
  // The delegate is looked up by the real extension, not a hard-coded "out".
  EXPECT_TRUE(contains(error, "\".log\""));
}

// When a delegate is found but fails, its own diagnosis is the most specific
// thing available: it used to be discarded, leaving the dialog empty.
TEST(GenericOutputTest, delegateErrorIsPropagated)
{
  TemporaryFile fixture("genericoutput-truncated-orca.out",
                        "           * O   R   C   A *\n\ntruncated\n");

  ORCAOutput orca;
  Molecule orcaMolecule;
  ASSERT_FALSE(orca.readFile(fixture.name(), orcaMolecule));
  const std::string orcaError = orca.error();
  ASSERT_FALSE(orcaError.empty());

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));

  const std::string error = reader.error();
  // Which reader ran, on which file, and what it said.
  EXPECT_TRUE(contains(error, "ORCA"));
  EXPECT_TRUE(contains(error, fixture.name()));
  EXPECT_TRUE(contains(error, orcaError));
  EXPECT_EQ(reader.identifier(), std::string("Avogadro: Orca"));
}

// A file that does parse must stay silent - the new messages are only built on
// the failure paths.
TEST(GenericOutputTest, recognizedOutputReadsWithoutError)
{
  GenericOutput reader;
  Molecule molecule;
  ASSERT_TRUE(
    reader.readFile(AVOGADRO_DATA "/data/nwchem/auh2o.out", molecule));
  EXPECT_EQ(reader.error(), std::string());
  EXPECT_EQ(reader.identifier(), std::string("Avogadro: NWChem"));
  EXPECT_EQ(molecule.atomCount(), 7);
}

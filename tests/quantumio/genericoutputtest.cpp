/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>

#include <avogadro/io/fileformat.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/quantumio/genericoutput.h>
#include <avogadro/quantumio/orca.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::Io::FileFormatManager;
using Avogadro::QuantumIO::GenericOutput;
using Avogadro::QuantumIO::ORCAOutput;

namespace {

// The reader picks its delegate from the file name's extension, so the
// fixtures have to be real files with real extensions rather than strings.
class TemporaryFile
{
public:
  TemporaryFile(std::string name, const std::string& contents)
    : m_name(std::move(name))
  {
    std::ofstream file(m_name.c_str());
    file << contents;
  }

  ~TemporaryFile() { std::remove(m_name.c_str()); }

  const std::string& name() const { return m_name; }

private:
  std::string m_name;
};

// A stand-in for a script plugin: declares content patterns, claims an
// extension nothing else uses, and records that it was asked to read.
class PatternFormat : public FileFormat
{
public:
  PatternFormat(std::string id, const std::vector<std::string>& patterns,
                std::shared_ptr<int> readCount)
    : m_id(std::move(id)), m_patterns(patterns),
      m_readCount(std::move(readCount))
  {
  }

  Operations supportedOperations() const override { return Read | File; }
  FileFormat* newInstance() const override
  {
    return new PatternFormat(m_id, m_patterns, m_readCount);
  }
  std::string identifier() const override { return m_id; }
  std::string name() const override { return m_id; }
  std::string description() const override { return "Test format"; }
  std::string specificationUrl() const override { return ""; }
  std::vector<std::string> fileExtensions() const override
  {
    return { "testpattern" };
  }
  std::vector<std::string> mimeTypes() const override { return {}; }
  std::vector<std::string> contentPatterns() const override
  {
    return m_patterns;
  }

  bool read(std::istream&, Molecule& molecule) override
  {
    ++(*m_readCount);
    molecule.addAtom(6);
    return true;
  }

  bool write(std::ostream&, const Molecule&) override { return false; }

private:
  std::string m_id;
  std::vector<std::string> m_patterns;
  std::shared_ptr<int> m_readCount;
};

// Registers pattern formats and always removes them again, so nothing leaks
// into other tests in this binary.
class GenericOutputPatternTest : public testing::Test
{
protected:
  void TearDown() override
  {
    for (const std::string& id : m_registered)
      FileFormatManager::unregisterFormat(id);
  }

  std::shared_ptr<int> add(const std::string& id,
                           const std::vector<std::string>& patterns)
  {
    auto count = std::make_shared<int>(0);
    EXPECT_TRUE(FileFormatManager::registerFormat(
      new PatternFormat(id, patterns, count)));
    m_registered.push_back(id);
    return count;
  }

private:
  std::vector<std::string> m_registered;
};

bool contains(const std::string& haystack, const std::string& needle)
{
  return haystack.find(needle) != std::string::npos;
}

} // namespace

// A file nothing recognizes used to fail with one sentence that named neither
// the file nor the readers that were missing, which left "cannot open Gaussian
// output" bug reports with nothing to go on. Both fallbacks have to be named:
// which one is absent is what tells a user whether to install the cclib plugin
// or to go looking for Open Babel.
//
// The fixture is deliberately ".LOG": the format map is keyed on lower case,
// and Windows users routinely have upper-case extensions.
TEST(GenericOutputTest, unrecognizedOutputNamesTheMissingFallbacks)
{
  TemporaryFile fixture("genericoutput-unrecognized.LOG",
                        "Entering Link 1\nsome program we do not know\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));

  const std::string error = reader.error();
  // The fallbacks that were not available.
  EXPECT_TRUE(contains(error, "cclib"));
  EXPECT_TRUE(contains(error, "Open Babel"));
  // The delegate is looked up by the real extension, not a hard-coded "out",
  // and the extension is folded to lower case before the lookup.
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

// The real CP2K banner (lines 28-29 of a CP2K 2026.2 run) on the third line of
// a ".out" file hands the file to the plugin that declared it.
TEST_F(GenericOutputPatternTest, contentPatternSelectsPlugin)
{
  auto count = add("Test: CP2K", { "CP2K| version string" });
  TemporaryFile fixture(
    "genericoutput-pattern.out",
    "header\n\n CP2K| version string:   CP2K version 2026.2\n"
    " CP2K| source code revision number:  git:c92cc08\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_TRUE(reader.readFile(fixture.name(), molecule));
  EXPECT_EQ(*count, 1);
  EXPECT_EQ(molecule.atomCount(), 1);
  EXPECT_EQ(reader.identifier(), std::string("Test: CP2K"));
  EXPECT_EQ(reader.error(), std::string());
}

// A plugin pattern on the first line beats a built-in banner on a later line.
TEST_F(GenericOutputPatternTest, earlierPluginLineBeatsBuiltInBanner)
{
  auto count = add("Test: first", { "PLUGIN-BANNER" });
  TemporaryFile fixture("genericoutput-pattern-first.out",
                        "PLUGIN-BANNER\n           * O   R   C   A *\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_TRUE(reader.readFile(fixture.name(), molecule));
  EXPECT_EQ(*count, 1);
  EXPECT_EQ(reader.identifier(), std::string("Test: first"));
}

// And the reverse: a built-in banner on an earlier line wins. The truncated
// ORCA file fails to read, which is harmless; what matters is who ran.
TEST_F(GenericOutputPatternTest, earlierBuiltInBannerBeatsPlugin)
{
  auto count = add("Test: late", { "PLUGIN-BANNER" });
  TemporaryFile fixture("genericoutput-pattern-late.out",
                        "           * O   R   C   A *\nPLUGIN-BANNER\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));
  EXPECT_EQ(*count, 0);
  EXPECT_EQ(reader.identifier(), std::string("Avogadro: Orca"));
}

// Plugins matching the same line: the first one registered wins.
TEST_F(GenericOutputPatternTest, firstRegisteredWinsOnSameLine)
{
  auto firstCount = add("Test: one", { "SHARED" });
  auto secondCount = add("Test: two", { "SHARED" });
  TemporaryFile fixture("genericoutput-pattern-tie.out", "SHARED banner\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_TRUE(reader.readFile(fixture.name(), molecule));
  EXPECT_EQ(*firstCount, 1);
  EXPECT_EQ(*secondCount, 0);
}

// An empty pattern would match every line, so it must never select a format.
TEST_F(GenericOutputPatternTest, emptyPatternNeverMatches)
{
  auto count = add("Test: empty", { "" });
  TemporaryFile fixture("genericoutput-pattern-empty.out",
                        "some program we do not know\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));
  EXPECT_EQ(*count, 0);
  EXPECT_TRUE(contains(reader.error(), "Could not determine"));
}

// No match anywhere, and nothing else registered: the existing error.
TEST_F(GenericOutputPatternTest, noMatchKeepsExistingError)
{
  add("Test: unmatched", { "NEVER-PRESENT" });
  TemporaryFile fixture("genericoutput-pattern-none.out", "nothing here\n");

  GenericOutput reader;
  Molecule molecule;
  EXPECT_FALSE(reader.readFile(fixture.name(), molecule));
  EXPECT_TRUE(contains(reader.error(), "Could not determine"));
}

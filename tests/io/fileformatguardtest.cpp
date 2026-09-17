/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/io/fileformat.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;

// FileFormat::readMolecule() and writeMolecule() wrap the format's own read()
// and write() so that an exception escaping a parser becomes an error string
// rather than a call to std::terminate. Avogadro's own code does not throw,
// but std::vector::at(), std::stoi() and nlohmann's accessors all do, and the
// quantum chemistry readers reach them on malformed input.
//
// Fuzz builds compile the guard out on purpose, so that libFuzzer still sees
// an escaping exception as a crash. Both halves are checked below: the catch
// cases build only when the guard is present, and a matching escape case
// builds only when it is absent, so the gating itself is under test.

namespace {

/// What the stub format should do when asked to read or write.
enum class Behavior
{
  Succeed,
  ThrowStandard, // the std::out_of_range a bare .at() would give us
  ThrowUnknown   // something that does not derive from std::exception
};

/// A format that exists only to misbehave on demand.
class ThrowingFormat : public FileFormat
{
public:
  explicit ThrowingFormat(Behavior behavior) : m_behavior(behavior) {}

  Operations supportedOperations() const override
  {
    return ReadWrite | File | Stream | String;
  }

  FileFormat* newInstance() const override
  {
    return new ThrowingFormat(m_behavior);
  }

  std::string identifier() const override { return "Avogadro: Throwing"; }
  std::string name() const override { return "Throwing"; }
  std::string description() const override { return "A test-only format."; }
  std::string specificationUrl() const override { return ""; }
  std::vector<std::string> fileExtensions() const override
  {
    return { "throw" };
  }
  std::vector<std::string> mimeTypes() const override
  {
    return { "chemical/x-throw" };
  }

  bool read(std::istream&, Molecule& molecule) override
  {
    // Add an atom first, so a test can tell whether a partly-built molecule
    // is handed back after a failure.
    molecule.addAtom(6);
    misbehave();
    return true;
  }

  bool write(std::ostream&, const Molecule&) override
  {
    misbehave();
    return true;
  }

private:
  void misbehave() const
  {
    switch (m_behavior) {
      case Behavior::ThrowStandard:
        throw std::out_of_range("index out of range");
      case Behavior::ThrowUnknown:
        throw 42;
      case Behavior::Succeed:
        break;
    }
  }

  Behavior m_behavior;
};

} // namespace

TEST(FileFormatGuardTest, readStringSucceedsWhenTheFormatBehaves)
{
  ThrowingFormat format(Behavior::Succeed);
  Molecule molecule;
  EXPECT_TRUE(format.readString("anything", molecule));
  EXPECT_TRUE(format.error().empty());
  EXPECT_EQ(molecule.atomCount(), static_cast<size_t>(1));
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

TEST(FileFormatGuardTest, readStringCatchesAStandardException)
{
  ThrowingFormat format(Behavior::ThrowStandard);
  Molecule molecule;
  EXPECT_FALSE(format.readString("anything", molecule));
  // The message has to reach the caller, or the user is told nothing.
  EXPECT_NE(format.error().find("index out of range"), std::string::npos);
}

TEST(FileFormatGuardTest, readStringCatchesANonStandardException)
{
  ThrowingFormat format(Behavior::ThrowUnknown);
  Molecule molecule;
  EXPECT_FALSE(format.readString("anything", molecule));
  EXPECT_FALSE(format.error().empty());
}

TEST(FileFormatGuardTest, readFileCatchesAStandardException)
{
  // readFile() reaches the parser by a different path than readString(), so
  // it needs its own case. Any readable file will do; the format ignores it.
  ThrowingFormat format(Behavior::ThrowStandard);
  Molecule molecule;
  EXPECT_FALSE(format.readFile(
    std::string(AVOGADRO_DATA) + "/data/xyz/methane.xyz", molecule));
  EXPECT_NE(format.error().find("index out of range"), std::string::npos);
}

TEST(FileFormatGuardTest, writeStringCatchesAStandardException)
{
  ThrowingFormat format(Behavior::ThrowStandard);
  Molecule molecule;
  molecule.addAtom(6);
  std::string output = "stale contents";
  EXPECT_FALSE(format.writeString(output, molecule));
  EXPECT_NE(format.error().find("index out of range"), std::string::npos);
  // A half-written document must not be handed back as though it were one.
  EXPECT_TRUE(output.empty());
}

TEST(FileFormatGuardTest, writeFileCatchesAStandardException)
{
  // writeFile() reaches the guard by a different route than writeString():
  // through open(), writeMolecule() and close(), and its result is combined
  // with the output-error flag before it is returned. Tests run with the
  // build directory as the working directory, which is writable.
  const std::string fileName("fileformatguardtest-output.tmp");
  ThrowingFormat format(Behavior::ThrowStandard);
  Molecule molecule;
  molecule.addAtom(6);
  EXPECT_FALSE(format.writeFile(fileName, molecule));
  EXPECT_NE(format.error().find("index out of range"), std::string::npos);
  // open() creates the file before write() is ever reached, so it exists even
  // though nothing usable was ever put in it.
  std::remove(fileName.c_str());
}

#else // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

TEST(FileFormatGuardTest, fuzzBuildsLetTheExceptionEscape)
{
  // The point of the fuzz configuration: the guard is gone, so the exception
  // reaches the caller. Under libFuzzer that is an abort and a reported
  // crash, which is the signal we want on an unchecked index.
  ThrowingFormat format(Behavior::ThrowStandard);
  Molecule molecule;
  EXPECT_THROW(format.readString("anything", molecule), std::out_of_range);
}

#endif // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

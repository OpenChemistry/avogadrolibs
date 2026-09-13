/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <avogadro/core/molecule.h>
#include <avogadro/io/smilesparser.h>
#include <avogadro/io/smileswriter.h>

#include <string>

using Avogadro::Core::Molecule;
using Avogadro::Io::SmilesParser;
using Avogadro::Io::SmilesWriter;

// SmilesFormat is write-only, so SmilesParser is not reachable through
// FileFormatManager::readString() and cannot use the generic fuzztest.cpp
// harness. Drive the parser directly instead.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
  // Long strings buy little coverage in a recursive-descent parser but cost a
  // lot of time per execution, and ring-closure bookkeeping is quadratic.
  if (Size > 4096)
    return 0;

  std::string input(reinterpret_cast<const char*>(Data), Size);

  SmilesParser parser;
  Molecule molecule;
  if (!parser.parse(input, molecule)) {
    // Touch the failure accessors: errorPosition() indexes into the input, so
    // an off-by-one there is worth catching.
    parser.error();
    parser.errorPosition();
    return 0;
  }

  parser.warnings();

  // atomMaps() is documented as one entry per atom of the molecule produced.
  if (parser.atomMaps().size() != molecule.atomCount())
    __builtin_trap();

  // Round-trip: the writer now gets a molecule with no coordinates, which is a
  // state most of the other format writers never see.
  SmilesWriter writer;
  std::string output;
  if (writer.write(molecule, output)) {
    Molecule reparsed;
    SmilesParser roundTrip;
    roundTrip.parse(output, reparsed);
  }

  return 0;
}

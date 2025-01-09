/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "fuzztest/fuzztest.h"
#include "iotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/matrix.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/unitcell.h>

#include <avogadro/io/cjsonformat.h>

using Avogadro::Core::Molecule;
using Avogadro::Io::CjsonFormat;

static const std::string cjsonDir = std::string(AVOGADRO_DATA) + "/data/cjson/";

void readCjson(const std::string& data)
{
  CjsonFormat cjson;
  Molecule molecule;
  bool success = cjson.readString(data, molecule);
  EXPECT_TRUE(success);
  EXPECT_EQ(cjson.error(), "");
}

FUZZ_TEST(AvogadroFuzzTests, readCjson)
  .WithSeeds(fuzztest::ReadFilesFromDirectory(cjsonDir));

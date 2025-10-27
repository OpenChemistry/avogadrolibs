/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/qcschema.h>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::QCSchema;

// does the basic read work?
TEST(QCSchemaTest, basicRead)
{
  QCSchema qcs;
  Molecule molecule;
  EXPECT_TRUE(qcs.readFile(
    AVOGADRO_DATA "/data/qcschema/output_json_1734290.json", molecule));
  ASSERT_EQ(qcs.error(), std::string());
}

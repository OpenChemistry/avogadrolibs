/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/qcschema.h>

#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Index;
using Avogadro::Vector3;
using Avogadro::Core::Atom;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::QCSchema;

using json = nlohmann::json;

namespace {

// cyclohexane (twist-boat), written by WebMO as the older "QC_JSON" variant
const char* webmoFile = AVOGADRO_DATA "/data/qcschema/output_json_1734401.json";

// build a water molecule directly, so the tests do not depend on a reader
Molecule water()
{
  Molecule molecule;
  molecule.addAtom(8).setPosition3d(Vector3(0.0, 0.0, 0.117));
  molecule.addAtom(1).setPosition3d(Vector3(0.0, 0.757, -0.469));
  molecule.addAtom(1).setPosition3d(Vector3(0.0, -0.757, -0.469));
  molecule.addBond(0, 1, 1);
  molecule.addBond(0, 2, 1);
  return molecule;
}

} // namespace

// the WebMO variant is in Angstroms with one-based connectivity indices
TEST(QCSchemaTest, readWebMO)
{
  QCSchema qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(webmoFile, molecule));
  EXPECT_EQ(qcs.error(), std::string());

  EXPECT_EQ(molecule.atomCount(), static_cast<Index>(18));
  EXPECT_EQ(molecule.bondCount(), static_cast<Index>(18));
  // the first bond is written as [1, 2, 1], and those one-based indices must
  // become the first and second atoms
  EXPECT_EQ(molecule.bond(0).atom1().index(), static_cast<Index>(0));
  EXPECT_EQ(molecule.bond(0).atom2().index(), static_cast<Index>(1));
  EXPECT_EQ(molecule.bond(0).order(), 1);
  // coordinates are already in Angstroms, so they are used as-is
  EXPECT_NEAR(molecule.atomPositions3d()[0].x(), 0.661709, 1e-6);
  EXPECT_NEAR(molecule.atomPositions3d()[0].y(), -1.220277, 1e-6);

  // WebMO names the energy after the method it ran, so this file has
  // "rhf_energy" (matching its method_energy_name of "RHF") and no
  // "total_energy" at all
  ASSERT_TRUE(molecule.hasData("totalEnergy"));
  EXPECT_NEAR(molecule.data("totalEnergy").toFloat(), -234.19029, 1e-3);
}

// Thermochemistry keys also end in "_energy" but are not the electronic
// energy. This file carries free_energy and internal_energy beside
// uhf_energy, and its method_energy_name of "HF" matches none of them, so the
// fallback has to pick uhf_energy rather than one of the thermochemistry ones.
TEST(QCSchemaTest, readWebMOEnergyIgnoresThermochemistry)
{
  QCSchema qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readFile(
    AVOGADRO_DATA "/data/qcschema/output_json_1734376.json", molecule));

  ASSERT_TRUE(molecule.hasData("totalEnergy"));
  EXPECT_NEAR(molecule.data("totalEnergy").toFloat(), -231.72097, 1e-3);
}

// A document following the specification is untouched by the WebMO fallback.
TEST(QCSchemaTest, totalEnergyWinsOverAMethodNamedKey)
{
  const char* input = R"({
    "schema_name": "QC_JSON",
    "symbols": ["H", "H"],
    "geometry": [0.0, 0.0, 0.0, 0.0, 0.0, 0.74],
    "properties": {
      "total_energy": { "units": "Hartree", "value": -1.5 },
      "uhf_energy": { "units": "Hartree", "value": -9.9 }
    }
  })";

  QCSchema qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readString(input, molecule));
  EXPECT_NEAR(molecule.data("totalEnergy").toFloat(), -1.5, 1e-6);
}

// the MolSSI variant is in bohr with zero-based connectivity indices
TEST(QCSchemaTest, readMolSSI)
{
  const char* input = R"({
    "schema_name": "qcschema_molecule",
    "schema_version": 3,
    "symbols": ["O", "H", "H"],
    "geometry": [0.0, 0.0, 0.2211, 0.0, 1.4306, -0.8863,
                 0.0, -1.4306, -0.8863],
    "molecular_charge": 0.0,
    "molecular_multiplicity": 1.0,
    "connectivity": [[0, 1, 1.0], [0, 2, 1.0]]
  })";

  QCSchema qcs;
  Molecule molecule;
  ASSERT_TRUE(qcs.readString(input, molecule));
  EXPECT_EQ(qcs.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), static_cast<Index>(3));
  ASSERT_EQ(molecule.bondCount(), static_cast<Index>(2));
  EXPECT_EQ(molecule.bond(0).atom1().index(), static_cast<Index>(0));
  EXPECT_EQ(molecule.bond(0).atom2().index(), static_cast<Index>(1));
  // 0.2211 bohr converted to Angstroms
  EXPECT_NEAR(molecule.atomPositions3d()[0].z(),
              0.2211 * Avogadro::BOHR_TO_ANGSTROM, 1e-6);
}

// the written file must conform to the MolSSI qcschema_molecule specification
TEST(QCSchemaTest, write)
{
  Molecule molecule = water();
  molecule.setData("name", std::string("water"));

  QCSchema qcs;
  std::string output;
  ASSERT_TRUE(qcs.writeString(output, molecule));

  json root = json::parse(output, nullptr, false);
  ASSERT_FALSE(root.is_discarded());

  EXPECT_EQ(root["schema_name"], "qcschema_molecule");
  EXPECT_EQ(root["schema_version"], 3);
  EXPECT_EQ(root["name"], "water");
  EXPECT_EQ(root["symbols"], json({ "O", "H", "H" }));

  // geometry is a flat array of 3 * nat coordinates in bohr
  ASSERT_TRUE(root["geometry"].is_array());
  ASSERT_EQ(root["geometry"].size(), 9u);
  EXPECT_NEAR(root["geometry"][2].get<double>(),
              0.117 / Avogadro::BOHR_TO_ANGSTROM, 1e-8);

  EXPECT_DOUBLE_EQ(root["molecular_charge"].get<double>(), 0.0);
  EXPECT_DOUBLE_EQ(root["molecular_multiplicity"].get<double>(), 1.0);

  // connectivity indices are zero-based
  ASSERT_EQ(root["connectivity"].size(), 2u);
  EXPECT_EQ(root["connectivity"][0], json({ 0, 1, 1.0 }));
  EXPECT_EQ(root["connectivity"][1], json({ 0, 2, 1.0 }));

  EXPECT_EQ(root["provenance"]["creator"], "Avogadro");
}

// connectivity has a minimum length of one, so it must be left out entirely
TEST(QCSchemaTest, writeWithoutBonds)
{
  Molecule molecule;
  molecule.addAtom(10).setPosition3d(Vector3(0.0, 0.0, 0.0));

  QCSchema qcs;
  std::string output;
  ASSERT_TRUE(qcs.writeString(output, molecule));

  json root = json::parse(output, nullptr, false);
  ASSERT_FALSE(root.is_discarded());
  EXPECT_EQ(root.find("connectivity"), root.end());
}

// custom elements have no symbol, so they cannot be represented
TEST(QCSchemaTest, writeCustomElementFails)
{
  Molecule molecule;
  molecule.addAtom(Avogadro::CustomElementMin).setPosition3d(Vector3::Zero());

  QCSchema qcs;
  std::string output;
  EXPECT_FALSE(qcs.writeString(output, molecule));
  EXPECT_NE(qcs.error(), std::string());
}

TEST(QCSchemaTest, writeEmptyFails)
{
  Molecule molecule;
  QCSchema qcs;
  std::string output;
  EXPECT_FALSE(qcs.writeString(output, molecule));
}

// reading back what we wrote must give the same molecule
TEST(QCSchemaTest, roundTrip)
{
  QCSchema reader;
  Molecule original;
  ASSERT_TRUE(reader.readFile(webmoFile, original));

  QCSchema writer;
  std::string output;
  ASSERT_TRUE(writer.writeString(output, original));

  QCSchema rereader;
  Molecule result;
  ASSERT_TRUE(rereader.readString(output, result));

  ASSERT_EQ(result.atomCount(), original.atomCount());
  ASSERT_EQ(result.bondCount(), original.bondCount());
  for (Index i = 0; i < original.atomCount(); ++i) {
    EXPECT_EQ(result.atom(i).atomicNumber(), original.atom(i).atomicNumber());
    EXPECT_LT(
      (result.atomPositions3d()[i] - original.atomPositions3d()[i]).norm(),
      1e-8);
  }
  for (Index i = 0; i < original.bondCount(); ++i) {
    EXPECT_EQ(result.bond(i).atom1().index(), original.bond(i).atom1().index());
    EXPECT_EQ(result.bond(i).atom2().index(), original.bond(i).atom2().index());
    EXPECT_EQ(result.bond(i).order(), original.bond(i).order());
  }
}

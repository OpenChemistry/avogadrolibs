/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/atom.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/molden.h>

#include <cmath>
#include <fstream>
#include <sstream>
#include <string>

using Avogadro::Vector3;
using Avogadro::Core::Array;
using Avogadro::Core::Atom;
using Avogadro::Core::BasisSet;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::Molecule;
using Avogadro::Io::FileFormat;
using Avogadro::QuantumIO::MoldenFile;

// does the basic read work
TEST(MoldenTest, basicRead)
{
  MoldenFile format;
  Molecule molecule;
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 3);
}

TEST(MoldenTest, readSparseMolecularOrbitals)
{
  static const char sparseMolden[] = R"([Molden Format]
[GTO]
    1 0
 s   6 1.00
     130.7093200    0.1543289700
      23.8088610    0.5353281400
       6.4436083    0.4446345400
       5.0331513    0.0000000000
       1.1695961    0.0000000000
       0.3803890    0.0000000000
 s   6 1.00
     130.7093200    0.0000000000
      23.8088610    0.0000000000
       6.4436083    0.0000000000
       5.0331513   -0.0999672300
       1.1695961    0.3995128300
       0.3803890    0.7001154700
 p   3 1.00
       5.0331513    0.1559162700
       1.1695961    0.6076837200
       0.3803890    0.3919573900

    2 0
 s   3 1.00
       3.4252509    0.1543289700
       0.6239137    0.5353281400
       0.1688554    0.4446345400

    3 0
 s   3 1.00
       3.4252509    0.1543289700
       0.6239137    0.5353281400
       0.1688554    0.4446345400

[SCFCONV]
scf-first  1  THROUGH   6
      -74.9111871529
      -74.9591249593
      -74.9643486920
      -74.9644734769
      -74.9644735608
      -74.9644735733
[TITLE]
*** Dalton interface to Molden, wave function type : HF             3Apr24   13:
[Atoms] AU
O          1     8         0.0000000000         0.0000000000         0.226016913
H          2     1         0.0000000000         1.4396179285        -0.904063875
H          3     1         0.0000000000        -1.4396179285        -0.904063875
[5D7F]
[9G]
[MO]
Sym= A
Ene=  -20.2442
Spin= Alpha
Occup=  2.0000
    1       -0.994158
    2       -0.026315
    5        0.004261
    6        0.005841
    7        0.005841
Sym= A
Ene=   -1.2636
Spin= Alpha
Occup=  2.0000
    1        0.233172
    2       -0.837489
    5        0.126492
    6       -0.157787
    7       -0.157787
Sym= A
Ene=   -0.6107
Spin= Alpha
Occup=  2.0000
    4       -0.607190
    6       -0.446173
    7        0.446173
Sym= A
Ene=   -0.4535
Spin= Alpha
Occup=  2.0000
    1        0.103065
    2       -0.535442
    5       -0.771827
    6        0.283175
    7        0.283175
Sym= A
Ene=   -0.3911
Spin= Alpha
Occup=  2.0000
    3        1.000000
Sym= A
Ene=    0.5959
Spin= Alpha
Occup=  0.0000
    1        0.130439
    2       -0.863428
    5        0.745860
    6        0.788155
    7        0.788155
Sym= A
Ene=    0.7268
Spin= Alpha
Occup=  0.0000
    4       -0.981914
    6        0.829084
    7       -0.829084
[End of Molden output from Dalton]
)";

  MoldenFile format;
  Molecule molecule;
  EXPECT_TRUE(format.readString(sparseMolden, molecule));
  ASSERT_EQ(format.error(), std::string());

  const auto* basis = dynamic_cast<const GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr);

  const auto moMatrix = basis->moMatrix();
  EXPECT_EQ(moMatrix.rows(), 7);
  EXPECT_EQ(moMatrix.cols(), 7);

  EXPECT_NEAR(moMatrix(0, 0), -0.994158, 1e-6);
  EXPECT_NEAR(moMatrix(1, 0), -0.026315, 1e-6);
  EXPECT_DOUBLE_EQ(moMatrix(2, 0), 0.0);
  EXPECT_DOUBLE_EQ(moMatrix(3, 0), 0.0);
  EXPECT_NEAR(moMatrix(4, 0), 0.004261, 1e-6);
  EXPECT_NEAR(moMatrix(3, 2), -0.607190, 1e-6);
  EXPECT_DOUBLE_EQ(moMatrix(0, 2), 0.0);
  EXPECT_DOUBLE_EQ(moMatrix(4, 2), 0.0);
  EXPECT_NEAR(moMatrix(2, 4), 1.0, 1e-6);
}

// Test that supportedOperations includes Write
TEST(MoldenTest, supportedOperations)
{
  MoldenFile format;
  auto ops = format.supportedOperations();
  EXPECT_TRUE(ops & FileFormat::Read);
  EXPECT_TRUE(ops & FileFormat::Write);
  EXPECT_TRUE(ops & FileFormat::File);
  EXPECT_TRUE(ops & FileFormat::Stream);
  EXPECT_TRUE(ops & FileFormat::String);
}

// Test basic write functionality
TEST(MoldenTest, basicWrite)
{
  MoldenFile format;
  Molecule molecule;

  // Read a test file first
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Verify key sections are present
  EXPECT_NE(output.find("[Molden Format]"), std::string::npos);
  EXPECT_NE(output.find("[Atoms]"), std::string::npos);
  EXPECT_NE(output.find("[GTO]"), std::string::npos);
  EXPECT_NE(output.find("[MO]"), std::string::npos);
}

// Round-trip test for atoms
TEST(MoldenTest, roundTripAtoms)
{
  MoldenFile format;
  Molecule molecule;

  // Read original file
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  // Store original values
  size_t originalAtomCount = molecule.atomCount();
  std::vector<unsigned char> originalAtomicNumbers;
  std::vector<Vector3> originalPositions;

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    originalAtomicNumbers.push_back(molecule.atomicNumber(i));
    originalPositions.push_back(molecule.atomPosition3d(i));
  }

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));

  // Read back
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readString(output, molecule2));
  ASSERT_EQ(format2.error(), std::string());

  // Verify atoms
  EXPECT_EQ(molecule2.atomCount(), originalAtomCount);

  for (size_t i = 0; i < molecule2.atomCount(); ++i) {
    EXPECT_EQ(molecule2.atomicNumber(i), originalAtomicNumbers[i]);

    Vector3 pos = molecule2.atomPosition3d(i);
    // Positions should match within reasonable tolerance (unit conversion)
    EXPECT_NEAR(pos.x(), originalPositions[i].x(), 1e-5);
    EXPECT_NEAR(pos.y(), originalPositions[i].y(), 1e-5);
    EXPECT_NEAR(pos.z(), originalPositions[i].z(), 1e-5);
  }
}

// Round-trip test for basis set
TEST(MoldenTest, roundTripBasisSet)
{
  MoldenFile format;
  Molecule molecule;

  // Read original file
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  const auto* originalBasis =
    dynamic_cast<const GaussianSet*>(molecule.basisSet());
  ASSERT_NE(originalBasis, nullptr);

  // Store original basis set info
  size_t originalShellCount = originalBasis->symmetry().size();
  size_t originalMOCount = originalBasis->molecularOrbitalCount();

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));

  // Read back
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readString(output, molecule2));
  ASSERT_EQ(format2.error(), std::string());

  const auto* newBasis = dynamic_cast<const GaussianSet*>(molecule2.basisSet());
  ASSERT_NE(newBasis, nullptr);

  // Verify basis set structure
  EXPECT_EQ(newBasis->symmetry().size(), originalShellCount);
  EXPECT_EQ(newBasis->molecularOrbitalCount(), originalMOCount);
}

// Round-trip test for molecular orbitals
TEST(MoldenTest, roundTripMolecularOrbitals)
{
  MoldenFile format;
  Molecule molecule;

  // Read original file
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  const auto* originalBasis =
    dynamic_cast<const GaussianSet*>(molecule.basisSet());
  ASSERT_NE(originalBasis, nullptr);

  // Store original MO data
  auto originalEnergies = originalBasis->moEnergy();
  auto originalSymLabels = originalBasis->symmetryLabels();

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));

  // Read back
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readString(output, molecule2));
  ASSERT_EQ(format2.error(), std::string());

  const auto* newBasis = dynamic_cast<const GaussianSet*>(molecule2.basisSet());
  ASSERT_NE(newBasis, nullptr);

  // Verify MO energies (converted through eV and back to Hartree)
  auto newEnergies = newBasis->moEnergy();
  ASSERT_EQ(newEnergies.size(), originalEnergies.size());

  for (size_t i = 0; i < newEnergies.size(); ++i) {
    // Allow some tolerance due to unit conversions
    EXPECT_NEAR(newEnergies[i], originalEnergies[i], 1e-6);
  }

  // Verify symmetry labels
  auto newSymLabels = newBasis->symmetryLabels();
  ASSERT_EQ(newSymLabels.size(), originalSymLabels.size());
}

// Test writing a molecule with vibration data
TEST(MoldenTest, writeVibrations)
{
  MoldenFile format;
  Molecule molecule;

  // Create a simple molecule with vibration data
  molecule.addAtom(8); // Oxygen
  molecule.addAtom(1); // Hydrogen
  molecule.addAtom(1); // Hydrogen

  molecule.setAtomPosition3d(0, Vector3(0.0, 0.0, 0.117));
  molecule.setAtomPosition3d(1, Vector3(0.0, 0.757, -0.469));
  molecule.setAtomPosition3d(2, Vector3(0.0, -0.757, -0.469));

  // Add vibration frequencies
  Array<double> frequencies;
  frequencies.push_back(1595.0); // Bending
  frequencies.push_back(3657.0); // Symmetric stretch
  frequencies.push_back(3756.0); // Asymmetric stretch
  molecule.setVibrationFrequencies(frequencies);

  // Add IR intensities
  Array<double> irIntensities;
  irIntensities.push_back(53.0);
  irIntensities.push_back(5.0);
  irIntensities.push_back(45.0);
  molecule.setVibrationIRIntensities(irIntensities);

  // Add normal mode displacements
  Array<Array<Vector3>> lx;

  // Mode 1 - bending
  Array<Vector3> mode1;
  mode1.push_back(Vector3(0.0, 0.0, 0.07));
  mode1.push_back(Vector3(0.0, 0.43, -0.56));
  mode1.push_back(Vector3(0.0, -0.43, -0.56));
  lx.push_back(mode1);

  // Mode 2 - symmetric stretch
  Array<Vector3> mode2;
  mode2.push_back(Vector3(0.0, 0.0, -0.07));
  mode2.push_back(Vector3(0.0, 0.58, 0.40));
  mode2.push_back(Vector3(0.0, -0.58, 0.40));
  lx.push_back(mode2);

  // Mode 3 - asymmetric stretch
  Array<Vector3> mode3;
  mode3.push_back(Vector3(0.0, 0.07, 0.0));
  mode3.push_back(Vector3(0.0, -0.43, -0.56));
  mode3.push_back(Vector3(0.0, -0.43, 0.56));
  lx.push_back(mode3);

  molecule.setVibrationLx(lx);

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Verify vibration sections are present
  EXPECT_NE(output.find("[FREQ]"), std::string::npos);
  EXPECT_NE(output.find("[FR-COORD]"), std::string::npos);
  EXPECT_NE(output.find("[FR-NORM-COORD]"), std::string::npos);
  EXPECT_NE(output.find("[INT]"), std::string::npos);
  EXPECT_NE(output.find("vibration 1"), std::string::npos);
  EXPECT_NE(output.find("vibration 2"), std::string::npos);
  EXPECT_NE(output.find("vibration 3"), std::string::npos);

  // Read back and verify
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readString(output, molecule2));
  ASSERT_EQ(format2.error(), std::string());

  auto readFreq = molecule2.vibrationFrequencies();
  ASSERT_EQ(readFreq.size(), 3);
  EXPECT_NEAR(readFreq[0], 1595.0, 1.0);
  EXPECT_NEAR(readFreq[1], 3657.0, 1.0);
  EXPECT_NEAR(readFreq[2], 3756.0, 1.0);

  auto readIR = molecule2.vibrationIRIntensities();
  ASSERT_EQ(readIR.size(), 3);
  EXPECT_NEAR(readIR[0], 53.0, 0.1);
  EXPECT_NEAR(readIR[1], 5.0, 0.1);
  EXPECT_NEAR(readIR[2], 45.0, 0.1);
}

// Test writing multiple coordinate sets (geometries)
TEST(MoldenTest, writeGeometries)
{
  MoldenFile format;
  Molecule molecule;

  // Create a simple molecule
  molecule.addAtom(8); // Oxygen
  molecule.addAtom(1); // Hydrogen
  molecule.addAtom(1); // Hydrogen

  // Set initial coordinates
  molecule.setAtomPosition3d(0, Vector3(0.0, 0.0, 0.117));
  molecule.setAtomPosition3d(1, Vector3(0.0, 0.757, -0.469));
  molecule.setAtomPosition3d(2, Vector3(0.0, -0.757, -0.469));

  // Add multiple coordinate sets (simulating an optimization)
  Array<Vector3> coords1;
  coords1.push_back(Vector3(0.0, 0.0, 0.117));
  coords1.push_back(Vector3(0.0, 0.757, -0.469));
  coords1.push_back(Vector3(0.0, -0.757, -0.469));
  molecule.setCoordinate3d(coords1, 0);

  Array<Vector3> coords2;
  coords2.push_back(Vector3(0.0, 0.0, 0.120));
  coords2.push_back(Vector3(0.0, 0.760, -0.470));
  coords2.push_back(Vector3(0.0, -0.760, -0.470));
  molecule.setCoordinate3d(coords2, 1);

  Array<Vector3> coords3;
  coords3.push_back(Vector3(0.0, 0.0, 0.115));
  coords3.push_back(Vector3(0.0, 0.755, -0.468));
  coords3.push_back(Vector3(0.0, -0.755, -0.468));
  molecule.setCoordinate3d(coords3, 2);

  ASSERT_EQ(molecule.coordinate3dCount(), 3);

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Verify geometry section is present
  EXPECT_NE(output.find("[GEOMETRIES]"), std::string::npos);
  EXPECT_NE(output.find("Frame 1"), std::string::npos);
  EXPECT_NE(output.find("Frame 2"), std::string::npos);
  EXPECT_NE(output.find("Frame 3"), std::string::npos);
}

// Test file round-trip (read file, write file, read back)
TEST(MoldenTest, fileRoundTrip)
{
  MoldenFile format;
  Molecule molecule;

  // Read original file
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/H2O.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  // Write to temp file
  EXPECT_TRUE(format.writeFile("h2o_roundtrip.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  // Read back
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readFile("h2o_roundtrip.molden", molecule2));
  ASSERT_EQ(format2.error(), std::string());

  // Verify basic properties match
  EXPECT_EQ(molecule2.atomCount(), molecule.atomCount());

  // Verify atoms
  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    EXPECT_EQ(molecule2.atomicNumber(i), molecule.atomicNumber(i));
  }

  // Verify basis set exists
  EXPECT_NE(molecule2.basisSet(), nullptr);
}

// Test writing SF4 (larger molecule with d orbitals)
TEST(MoldenTest, roundTripSF4)
{
  MoldenFile format;
  Molecule molecule;

  // Read SF4 file (has d orbitals)
  EXPECT_TRUE(
    format.readFile(AVOGADRO_DATA "/data/molden/SF4.molden", molecule));
  ASSERT_EQ(format.error(), std::string());

  ASSERT_EQ(molecule.atomCount(), 5);

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Read back
  MoldenFile format2;
  Molecule molecule2;
  EXPECT_TRUE(format2.readString(output, molecule2));
  ASSERT_EQ(format2.error(), std::string());

  EXPECT_EQ(molecule2.atomCount(), 5);

  // Verify sulfur atom
  EXPECT_EQ(molecule2.atomicNumber(0), 16); // S

  // Verify fluorine atoms
  for (size_t i = 1; i < 5; ++i) {
    EXPECT_EQ(molecule2.atomicNumber(i), 9); // F
  }
}

// Test that empty molecule can be written
TEST(MoldenTest, writeEmptyMolecule)
{
  MoldenFile format;
  Molecule molecule;

  // Write empty molecule (just atoms section with nothing in it)
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Should at least have the header
  EXPECT_NE(output.find("[Molden Format]"), std::string::npos);
  EXPECT_NE(output.find("[Atoms]"), std::string::npos);
}

// Test writing molecule without basis set
TEST(MoldenTest, writeNoBasisSet)
{
  MoldenFile format;
  Molecule molecule;

  // Create a simple molecule without basis set
  molecule.addAtom(6); // Carbon
  molecule.addAtom(1); // Hydrogen
  molecule.addAtom(1);
  molecule.addAtom(1);
  molecule.addAtom(1);

  molecule.setAtomPosition3d(0, Vector3(0.0, 0.0, 0.0));
  molecule.setAtomPosition3d(1, Vector3(1.09, 0.0, 0.0));
  molecule.setAtomPosition3d(2, Vector3(-0.36, 1.03, 0.0));
  molecule.setAtomPosition3d(3, Vector3(-0.36, -0.51, 0.89));
  molecule.setAtomPosition3d(4, Vector3(-0.36, -0.51, -0.89));

  // Write to string
  std::string output;
  EXPECT_TRUE(format.writeString(output, molecule));
  ASSERT_EQ(format.error(), std::string());

  // Should have atoms but no GTO or MO sections
  EXPECT_NE(output.find("[Molden Format]"), std::string::npos);
  EXPECT_NE(output.find("[Atoms]"), std::string::npos);
  EXPECT_NE(output.find("C "), std::string::npos);
  EXPECT_NE(output.find("H "), std::string::npos);

  // Should NOT have GTO or MO sections (no basis set)
  EXPECT_EQ(output.find("[GTO]"), std::string::npos);
  EXPECT_EQ(output.find("[MO]"), std::string::npos);
}

// Regression test: malformed GTO section should fail gracefully.
TEST(MoldenTest, invalidGtoDoesNotCrash)
{
  MoldenFile format;
  Molecule molecule;

  const std::string input = "[Molden Format]\n"
                            "[Atoms]\n"
                            "O 1 8 0.0 0.0 0.0\n"
                            "[GTO]\n"
                            " 1 0\n"
                            " s 1 1.0\n"
                            "\n";

  EXPECT_FALSE(format.readString(input, molecule));
  EXPECT_NE(format.error(), std::string());
}

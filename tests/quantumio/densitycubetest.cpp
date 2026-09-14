/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quantumiotests.h"

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/gaussiansettools.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>

#include <avogadro/quantumio/gaussiancube.h>
#include <avogadro/quantumio/gaussianfchk.h>

#include <algorithm>
#include <cmath>
#include <string>

using Avogadro::Vector3i;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::GaussianSetTools;
using Avogadro::Core::Molecule;
using Avogadro::QuantumIO::GaussianCube;
using Avogadro::QuantumIO::GaussianFchk;

namespace {

// End-to-end validation of the Gaussian basis evaluator against Gaussian
// itself. Each case pairs a formatted checkpoint file with an SCF electron
// density cube from that same calculation, so the reference is an
// independent oracle: an electron density is a physical observable and does
// not depend on any basis ordering or normalization convention, while
// everything between reading the fchk and filling the cube does.
//
// This complements GaussianShellNormalizationTest in tests/core. That test
// checks each shell in isolation -- unit norm, mutual orthogonality,
// orthogonality to lower angular momenta -- which pins the conventions down
// but cannot see an error applied consistently on both sides of its own
// arithmetic. This test can, because Gaussian computed the reference.
//
// The density is compared rather than individual molecular orbitals because
// it is invariant under orbital sign flips and under rotations within a
// degenerate set, so a failure here is a real disagreement rather than a
// labelling difference.
//
// Coverage (shell types taken from each fchk's own "Shell types" block;
// negative means spherical):
//
//   h2o-vdz        s, p, -2        spherical d
//   h2o-vdz-6d     s, p,  2        Cartesian d
//   h2o-vtz        adds -3         spherical f
//   h2o-vtz-10f    adds  3         Cartesian f
//   h2o-vqz        adds -3, -4     spherical g
//   h2o-vqz-15g    adds  3,  4     Cartesian f and g
struct DensityCase
{
  std::string name;
  std::string stem;   // shared prefix of the .fchk.gz / .cube.gz pair
  std::string covers; // which shell types this case exercises
};

std::ostream& operator<<(std::ostream& out, const DensityCase& testCase)
{
  return out << testCase.name;
}

std::string dataPath(const std::string& stem, const std::string& suffix)
{
  return std::string(AVOGADRO_DATA) + "/data/integration/" + stem + suffix;
}

} // namespace

class DensityCubeTest : public ::testing::TestWithParam<DensityCase>
{};

TEST_P(DensityCubeTest, densityMatchesGaussian)
{
  const DensityCase& testCase = GetParam();

  // Both files are gzip compressed; FileFormat::open() sniffs the content
  // and decompresses transparently, so nothing special is needed here.
  Molecule referenceMolecule;
  GaussianCube cubeReader;
  ASSERT_TRUE(
    cubeReader.readFile(dataPath(testCase.stem, ".cube.gz"), referenceMolecule))
    << cubeReader.error();
  ASSERT_EQ(referenceMolecule.cubeCount(), static_cast<Avogadro::Index>(1));
  const Cube* reference = referenceMolecule.cube(0);
  ASSERT_NE(reference, nullptr);

  // The wave function, from the same calculation.
  Molecule molecule;
  GaussianFchk fchkReader;
  ASSERT_TRUE(
    fchkReader.readFile(dataPath(testCase.stem, ".fchk.gz"), molecule))
    << fchkReader.error();
  auto* basis = dynamic_cast<GaussianSet*>(molecule.basisSet());
  ASSERT_NE(basis, nullptr) << "fchk did not yield a GaussianSet";

  const Vector3i dim = reference->dimensions();

  // Precondition on the reference data itself. Integrating the reference
  // over the box must land near the electron count the wave function
  // carries: a coarse grid and a finite box lose a little density, but
  // never a whole shell's worth.
  //
  // This guards a failure mode that is otherwise very hard to read off the
  // comparison below. A cube generated from a valence-only density (core
  // orbitals excluded) agrees with an all-electron calculation everywhere
  // except within about a bohr of a nucleus, where it is wrong by more than
  // an order of magnitude -- the comparison would report an enormous
  // deviation at a single grid point and give no hint as to why.
  const double angstromToBohr = 1.0 / 0.52917721092;
  const double voxel = reference->spacing().x() * reference->spacing().y() *
                       reference->spacing().z() * std::pow(angstromToBohr, 3.0);
  double referenceSum = 0.0;
  for (int i = 0; i < dim.x(); ++i)
    for (int j = 0; j < dim.y(); ++j)
      for (int k = 0; k < dim.z(); ++k)
        referenceSum += reference->value(i, j, k);
  const double referenceElectrons = referenceSum * voxel;
  const double expectedElectrons = basis->electronCount();
  ASSERT_GT(referenceElectrons, 0.9 * expectedElectrons)
    << testCase.stem << ".cube.gz integrates to " << referenceElectrons
    << " electrons, but its wave function has " << expectedElectrons
    << ". That is the signature of a valence-only density cube (core "
       "orbitals excluded); regenerate it from the full SCF density.";

  // Evaluate on exactly the reference grid -- setLimits(const Cube&) copies
  // the origin, dimensions and spacing, so this is a pointwise comparison
  // with no interpolation anywhere.
  Cube calculated;
  ASSERT_TRUE(calculated.setLimits(*reference));
  GaussianSetTools tools(&molecule);
  ASSERT_TRUE(tools.calculateElectronDensity(calculated));
  ASSERT_EQ(calculated.dimensions(), dim);

  // Density spans orders of magnitude across the box -- hundreds of
  // electrons/bohr^3 beside the oxygen, essentially zero in the corners --
  // so a single absolute tolerance would be meaningless. Compare relative
  // to the local value with an absolute floor for the near-zero region. The
  // floor also absorbs the reference's own precision: Gaussian writes cube
  // values in E13.5, about five significant figures.
  const double relativeTolerance = 1e-3;
  // The absolute floor is set by GaussianSetTools::calculateShellCutoff,
  // which deliberately stops evaluating each shell once it falls below
  // about 3e-5 of its peak amplitude. That is a performance tradeoff, not
  // an error, but it makes Avogadro very slightly low in the diffuse tail:
  // beyond ~3 bohr from every nucleus, where the density is ~1e-3, the
  // shortfall is a few times 1e-6. A floor of 2e-5 absorbs that while
  // staying far below the deviations a real convention error produces --
  // those run to ~1e-2 in the bonding region, three orders of magnitude
  // larger.
  const double absoluteFloor = 2e-5;

  double worstRelative = 0.0;
  double worstAbsolute = 0.0;
  Vector3i worstAt(0, 0, 0);
  double calculatedSum = 0.0;

  for (int i = 0; i < dim.x(); ++i) {
    for (int j = 0; j < dim.y(); ++j) {
      for (int k = 0; k < dim.z(); ++k) {
        const double ref = reference->value(i, j, k);
        const double got = calculated.value(i, j, k);
        calculatedSum += got;

        const double absolute = std::abs(got - ref);
        worstAbsolute = std::max(worstAbsolute, absolute);
        if (absolute > relativeTolerance * std::abs(ref) + absoluteFloor) {
          const double relative = absolute / (std::abs(ref) + absoluteFloor);
          if (relative > worstRelative) {
            worstRelative = relative;
            worstAt = Vector3i(i, j, k);
          }
        }
      }
    }
  }

  EXPECT_EQ(worstRelative, 0.0)
    << testCase.name << " (" << testCase.covers
    << "): density disagrees with Gaussian by up to " << (worstRelative * 100.0)
    << "% at grid point (" << worstAt.x() << ", " << worstAt.y() << ", "
    << worstAt.z() << "); worst absolute deviation over the grid was "
    << worstAbsolute;

  // States a uniform scale error in electrons rather than percent, which is
  // the easier number to act on when a whole shell is mis-normalized.
  EXPECT_NEAR(calculatedSum * voxel, referenceElectrons,
              1e-3 * referenceElectrons)
    << testCase.name << ": integrated density differs from the reference";
}

INSTANTIATE_TEST_SUITE_P(
  Basis, DensityCubeTest,
  ::testing::Values(
    DensityCase{ "vdz_spherical_d", "h2o-vdz", "s, p, spherical d (-2)" },
    DensityCase{ "vdz_cartesian_d", "h2o-vdz-6d", "s, p, Cartesian d (2)" },
    DensityCase{ "vtz_spherical_f", "h2o-vtz", "adds spherical f (-3)" },
    DensityCase{ "vtz_cartesian_f", "h2o-vtz-10f", "adds Cartesian f (3)" },
    DensityCase{ "vqz_spherical_g", "h2o-vqz", "adds spherical f/g (-3, -4)" },
    DensityCase{ "vqz_cartesian_g", "h2o-vqz-15g",
                 "adds Cartesian f/g (3, 4)" }),
  [](const ::testing::TestParamInfo<DensityCase>& info) {
    return info.param.name;
  });

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/calc/lennardjones.h>

#include <avogadro/core/molecule.h>

#include <algorithm>
#include <cmath>

using namespace Avogadro::Calc;
using namespace Avogadro::Core;
using namespace Avogadro;

TEST(LennardJonesTest, EvaluateMatchesValueAndGradient)
{
  Molecule molecule;
  molecule.addAtom(6);
  molecule.addAtom(8);
  molecule.addAtom(1);

  LennardJones calculator;
  calculator.setMolecule(&molecule);

  Eigen::VectorXd positions(9);
  positions << 0.0, 0.0, 0.0, 1.45, 0.2, 0.1, -0.4, 1.1, -0.2;

  const Real expectedEnergy = calculator.value(positions);
  Eigen::VectorXd expectedGradient = Eigen::VectorXd::Zero(positions.size());
  calculator.gradient(positions, expectedGradient);

  Eigen::VectorXd fusedGradient(1); // intentional wrong size to validate resize
  const Real fusedEnergy = calculator.evaluate(positions, &fusedGradient);

  EXPECT_NEAR(fusedEnergy, expectedEnergy,
              std::max(1e-10, 1e-12 * std::fabs(expectedEnergy)));
  ASSERT_EQ(fusedGradient.size(), expectedGradient.size());
  for (int i = 0; i < expectedGradient.size(); ++i) {
    EXPECT_NEAR(fusedGradient[i], expectedGradient[i],
                std::max(1e-10, 1e-9 * std::fabs(expectedGradient[i])));
  }
}

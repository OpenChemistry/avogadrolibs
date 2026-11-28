// Headless WebAssembly smoke test: read a molecule, evaluate UFF, optimize.
#include <avogadro/calc/energyoptimizer.h>
#include <avogadro/calc/uff.h>
#include <avogadro/core/molecule.h>
#include <avogadro/io/cjsonformat.h>

#include <cmath>
#include <iostream>
#include <string>

using namespace Avogadro;

int main()
{
  // A distorted water: long O-H bonds and a wide angle.
  const std::string cjson = R"({
    "chemicalJson": 1,
    "atoms": {
      "elements": { "number": [8, 1, 1] },
      "coords": { "3d": [0.0, 0.0, 0.0, 1.2, 0.0, 0.0, -0.4, 1.1, 0.0] }
    },
    "bonds": {
      "connections": { "index": [0, 1, 0, 2] },
      "order": [1, 1]
    }
  })";

  Core::Molecule molecule;
  Io::CjsonFormat cjsonFormat;
  if (!cjsonFormat.readString(cjson, molecule) || molecule.atomCount() != 3) {
    std::cerr << "FAIL: could not read CJSON: " << cjsonFormat.error() << "\n";
    return 1;
  }

  Calc::UFF uff;
  uff.setMolecule(&molecule);

  Eigen::VectorXd x(9);
  for (Index i = 0; i < 3; ++i)
    x.segment<3>(3 * i) = molecule.atomPosition3d(i);

  const double before = uff.value(x);

  Calc::OptimizationOptions options;
  options.algorithm = Calc::OptimizationAlgorithm::Lbfgs;
  options.chunkIterations = 100;
  if (!Calc::optimizeSteps(uff, x, options)) {
    std::cerr << "FAIL: optimizeSteps returned false\n";
    return 1;
  }
  const double after = uff.value(x);

  std::cout << "UFF energy before: " << before << " kJ/mol\n"
            << "UFF energy after:  " << after << " kJ/mol\n";

  if (!std::isfinite(before) || !std::isfinite(after) || !(after < before)) {
    std::cerr << "FAIL: optimization did not lower the energy\n";
    return 1;
  }
  std::cout << "OK\n";
  return 0;
}

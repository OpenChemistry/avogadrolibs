/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/cube.h>
#include <avogadro/core/gaussianset.h>
#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/gaussiansetconcurrent.h>

#include <QCoreApplication>
#include <QSignalSpy>

#include <utility>

using Avogadro::Vector3;
using Avogadro::Vector3i;
using Avogadro::Core::BasisSet;
using Avogadro::Core::Cube;
using Avogadro::Core::GaussianSet;
using Avogadro::Core::Molecule;
using Avogadro::QtGui::GaussianSetConcurrent;

namespace {

// finished() is delivered through the event loop, which needs an application.
void ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return;
  static int argc = 1;
  static char name[] = "GaussianSetConcurrentTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
}

// One hydrogen atom with a single S shell and one MO.
void fillHydrogen(Molecule& m)
{
  m.addAtom(1);
  m.setAtomPosition3d(0, Vector3::Zero());
  auto* basis = new GaussianSet;
  basis->setMolecule(&m);
  basis->addBasis(0, GaussianSet::S);
  basis->addGto(0, 1.0, 1.0);
  basis->setMolecularOrbitals({ 1.0 });
  m.setBasisSet(basis);
}

void setUpCube(Cube& cube)
{
  cube.setLimits(Vector3(-2.0, -2.0, -2.0), Vector3i(9, 9, 9), 0.5f);
}

// The value at the centre of a cube set up by setUpCube().
float centre(const Cube& cube)
{
  return cube.value(4, 4, 4);
}
} // namespace

// Setting up a calculation writes into the basis set, so a basis set an undo
// snapshot shares has to be copied for the live molecule first.
TEST(GaussianSetConcurrentTest, setMoleculeDetachesASharedBasisSet)
{
  ensureApp();
  Molecule live;
  fillHydrogen(live);
  const Molecule snapshot(live);
  const BasisSet* shared = snapshot.basisSet();
  ASSERT_EQ(std::as_const(live).basisSet(), shared);

  GaussianSetConcurrent calculator;
  calculator.setMolecule(&live);
  EXPECT_NE(std::as_const(live).basisSet(), shared);
  EXPECT_EQ(snapshot.basisSet(), shared);
}

// The workers read the basis set the calculation was set up with. If the
// molecule detaches from it and the only other owner goes away, the
// calculator's handle has to keep it alive (ASan reports a use after free
// otherwise).
TEST(GaussianSetConcurrentTest, handleKeepsTheBasisSetAliveForTheJob)
{
  ensureApp();
  Molecule live;
  fillHydrogen(live);
  GaussianSetConcurrent calculator;
  calculator.setMolecule(&live);
  const BasisSet* used = std::as_const(live).basisSet();

  {
    Molecule snapshot(live);
    ASSERT_NE(live.basisSet(), used); // detaches: the handle holds it too
  }

  Cube cube;
  setUpCube(cube);
  ASSERT_TRUE(calculator.calculateMolecularOrbital(&cube, 0));
  calculator.watcher().waitForFinished();
  EXPECT_GT(centre(cube), 0.0f);
}

// The handle is released when the job finishes, so holding nothing between
// jobs, a further calculation sets itself up again from the molecule. The
// basis set the first job used may have been copied away and freed meanwhile
// (ASan reports a use after free if the calculator reads it).
TEST(GaussianSetConcurrentTest, laterCalculationsSetUpAgain)
{
  ensureApp();
  Molecule live;
  fillHydrogen(live);
  GaussianSetConcurrent calculator;
  QSignalSpy finished(&calculator, &GaussianSetConcurrent::finished);

  Cube first;
  setUpCube(first);
  calculator.setMolecule(&live);
  ASSERT_TRUE(calculator.calculateMolecularOrbital(&first, 0));
  ASSERT_TRUE(finished.wait(5000));
  EXPECT_GT(centre(first), 0.0f);

  // No longer holding the basis set, the next mutable access does not copy.
  const BasisSet* own = std::as_const(live).basisSet();
  EXPECT_EQ(live.basisSet(), own);

  // Copy the molecule, detach the live one, and free the copy: the basis set
  // the first job used is gone.
  {
    const Molecule snapshot(live);
    ASSERT_NE(live.basisSet(), own);
  }

  Cube second;
  setUpCube(second);
  ASSERT_TRUE(calculator.calculateMolecularOrbital(&second, 0));
  ASSERT_TRUE(finished.wait(5000));
  EXPECT_FLOAT_EQ(centre(second), centre(first));

  Cube density;
  setUpCube(density);
  EXPECT_TRUE(calculator.calculateElectronDensity(&density));
  ASSERT_TRUE(finished.wait(5000));
}

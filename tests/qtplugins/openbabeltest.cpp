/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obcharges.h"

#include <avogadro/core/molecule.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QStandardPaths>
#include <QtCore/QString>
#include <QtCore/QTimer>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::OBCharges;

namespace {

bool haveObabel()
{
  if (!qEnvironmentVariableIsEmpty("AVO_OBABEL_EXECUTABLE"))
    return true;
  return !QStandardPaths::findExecutable("obabel").isEmpty();
}

} // namespace

// partialCharges() is called from QAbstractItemModel::data() while a view is
// painting, so it must never run the event loop: a nested paint of the same
// window crashes.
TEST(OpenBabelCommandTest, ChargesDoNotRunTheEventLoop)
{
  if (!haveObabel())
    GTEST_SKIP() << "obabel is not available";

  // Ethanol, with hydrogens.
  Avogadro::Core::Molecule mol;
  const unsigned char elements[] = { 6, 6, 8, 1, 1, 1, 1, 1, 1 };
  const double xyz[][3] = {
    { 0.000, 0.000, 0.000 },   { 1.520, 0.000, 0.000 },
    { 2.000, 1.340, 0.000 },   { -0.390, 1.020, 0.000 },
    { -0.390, -0.510, 0.880 }, { -0.390, -0.510, -0.880 },
    { 1.880, -0.520, 0.890 },  { 1.880, -0.520, -0.890 },
    { 2.960, 1.340, 0.000 },
  };
  for (int i = 0; i < 9; ++i)
    mol.addAtom(elements[i])
      .setPosition3d(Avogadro::Vector3(xyz[i][0], xyz[i][1], xyz[i][2]));
  const unsigned int bonds[][2] = { { 0, 1 }, { 1, 2 }, { 0, 3 }, { 0, 4 },
                                    { 0, 5 }, { 1, 6 }, { 1, 7 }, { 2, 8 } };
  for (const auto& b : bonds)
    mol.addBond(b[0], b[1], 1);

  bool timerFired = false;
  QTimer::singleShot(0, [&timerFired]() { timerFired = true; });

  const OBCharges model("gasteiger");
  const Avogadro::MatrixX charges =
    model.partialCharges(static_cast<const Avogadro::Core::Molecule&>(mol));

  EXPECT_FALSE(timerFired) << "partialCharges() ran the event loop";
  EXPECT_EQ(charges.rows(), static_cast<Eigen::Index>(mol.atomCount()));

  // The timer is still pending, not lost.
  QCoreApplication::processEvents();
  EXPECT_TRUE(timerFired);
}

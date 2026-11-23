/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obcharges.h"
#include "obfileformat.h"
#include "obprocess.h"

#include <avogadro/core/molecule.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtCore/QTimer>

#include <gtest/gtest.h>

#include <memory>
#include <string>

using Avogadro::QtPlugins::OBCharges;

namespace {

// Ask OBProcess, so the test finds obabel exactly where the plugin would.
bool haveObabel()
{
  return !Avogadro::QtPlugins::OBProcess().version().isEmpty();
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

// With no atoms there is nothing to run obabel on, and no first charge to
// adjust.
TEST(OpenBabelCommandTest, ChargesForAnEmptyMolecule)
{
  const Avogadro::Core::Molecule mol;
  const OBCharges model("gasteiger");
  const Avogadro::MatrixX charges = model.partialCharges(mol);
  EXPECT_EQ(0, charges.rows());
}

// Same for reading through Open Babel: file formats are called from code that
// is itself running in an event handler (or a worker thread).
TEST(OpenBabelCommandTest, FileReadDoesNotRunTheEventLoop)
{
  if (!haveObabel())
    GTEST_SKIP() << "obabel is not available";

  Avogadro::QtPlugins::OBFileFormat format(
    "XYZ via Open Babel", "Avogadro: OBXYZ", "XYZ", "", { "xyz" },
    { "chemical/x-xyz" }, "cml", false);

  const std::string input = "3\nwater\n"
                            "O 0.000 0.000 0.000\n"
                            "H 0.960 0.000 0.000\n"
                            "H -0.240 0.930 0.000\n";

  bool timerFired = false;
  QTimer::singleShot(0, [&timerFired]() { timerFired = true; });

  Avogadro::Core::Molecule mol;
  EXPECT_TRUE(format.readString(input, mol)) << format.error();

  EXPECT_FALSE(timerFired) << "read() ran the event loop";
  EXPECT_EQ(mol.atomCount(), 3u);

  QCoreApplication::processEvents();
  EXPECT_TRUE(timerFired);
}

// BackgroundFileFormat reads on a worker thread, where the process, its
// listener, and the wait all have to stay on that thread.
TEST(OpenBabelCommandTest, FileReadOnWorkerThread)
{
  if (!haveObabel())
    GTEST_SKIP() << "obabel is not available";

  // The worker owns its data, so it stays valid if the test gives up on it.
  struct Result
  {
    Avogadro::Core::Molecule mol;
    bool ok = false;
  };
  auto result = std::make_shared<Result>();
  QThread* thread = QThread::create([result]() {
    const std::string input = "3\nwater\n"
                              "O 0.000 0.000 0.000\n"
                              "H 0.960 0.000 0.000\n"
                              "H -0.240 0.930 0.000\n";
    Avogadro::QtPlugins::OBFileFormat format(
      "XYZ via Open Babel", "Avogadro: OBXYZ", "XYZ", "", { "xyz" },
      { "chemical/x-xyz" }, "cml", false);
    result->ok = format.readString(input, result->mol);
  });
  thread->start();
  if (!thread->wait(30000)) {
    // Deleting a running QThread aborts, and terminate() is unsafe, so leave
    // it running; the read gives up on obabel by itself.
    FAIL() << "reading on the worker thread did not finish within 30 s";
  }
  delete thread;

  EXPECT_TRUE(result->ok);
  EXPECT_EQ(result->mol.atomCount(), 3u);
}

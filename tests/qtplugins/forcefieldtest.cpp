/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "energywindow.h"
#include "obmmenergy.h"

#include <QtCore/QtGlobal>

#include <gtest/gtest.h>

using Avogadro::QtPlugins::OBMMEnergy;

namespace {

// Sets AVO_OBMM_EXECUTABLE for one test and restores it afterwards.
class ObmmEnvGuard
{
public:
  explicit ObmmEnvGuard(const char* value)
    : m_hadValue(qEnvironmentVariableIsSet(name)), m_oldValue(qgetenv(name))
  {
    qputenv(name, value);
  }

  ~ObmmEnvGuard()
  {
    if (m_hadValue)
      qputenv(name, m_oldValue);
    else
      qunsetenv(name);
  }

private:
  static constexpr const char* name = "AVO_OBMM_EXECUTABLE";
  bool m_hadValue;
  QByteArray m_oldValue;
};

} // namespace

TEST(ForcefieldCommandTest, obmmMissingAbsoluteOverride)
{
  ObmmEnvGuard guard("/nonexistent/dir/obmm");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmMissingRelativeOverride)
{
  ObmmEnvGuard guard("avogadro-no-such-obmm-binary");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}

#ifndef _WIN32
TEST(ForcefieldCommandTest, obmmExistingAbsoluteOverride)
{
  ObmmEnvGuard guard("/bin/sh");
  EXPECT_TRUE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmExistingOverrideOnPath)
{
  ObmmEnvGuard guard("sh");
  EXPECT_TRUE(OBMMEnergy::isAvailable());
}

TEST(ForcefieldCommandTest, obmmNonExecutableOverride)
{
  // A directory is not an executable
  ObmmEnvGuard guard("/tmp");
  EXPECT_FALSE(OBMMEnergy::isAvailable());
}
#endif

// --- EnergyWindow ---------------------------------------------------------

using Avogadro::QtPlugins::EnergyWindow;

TEST(EnergyWindowTest, LongChunksAreTheirOwnWindow)
{
  // Chunks >= window: identical to a per-chunk |dE| / chunkRan test.
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(20, 100.0, tol));      // first chunk only anchors
  EXPECT_FALSE(w.update(40, 90.0, tol));       // 0.5 per iteration
  EXPECT_TRUE(w.update(60, 90.0 - 1e-3, tol)); // 5e-5 per iteration
}

TEST(EnergyWindowTest, ShortChunksAccumulateToTheWindow)
{
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(1, 50.0, tol));
  // One-iteration chunks with a tiny step: no verdict until 10 iterations
  // have passed since the anchor.
  for (unsigned int i = 2; i <= 10; ++i)
    EXPECT_FALSE(w.update(i, 50.0, tol)) << i;
  EXPECT_TRUE(w.update(11, 50.0, tol));
}

TEST(EnergyWindowTest, MeanOverWindowNotLastStep)
{
  // A single tiny step inside a window of real progress must not stop it.
  EnergyWindow w;
  const double tol = 1e-4;
  EXPECT_FALSE(w.update(1, 50.0, tol));
  double e = 50.0;
  for (unsigned int i = 2; i <= 10; ++i) {
    e -= (i == 5) ? 0.0 : 0.01;
    EXPECT_FALSE(w.update(i, e, tol));
  }
  EXPECT_FALSE(w.update(11, e - 0.01, tol)); // 0.09 / 10 per iteration
}

TEST(EnergyWindowTest, AnchorMovesAndResets)
{
  EnergyWindow w;
  const double tol = 1e-4;
  w.update(10, 10.0, tol);
  EXPECT_FALSE(w.update(20, 5.0, tol));
  // The anchor is now (20, 5.0): a flat next window converges.
  EXPECT_TRUE(w.update(30, 5.0, tol));
  w.reset();
  EXPECT_FALSE(w.update(40, 5.0, tol)); // re-anchors rather than testing
}

TEST(EnergyWindowTest, ZeroEnergyStillTested)
{
  EnergyWindow w;
  EXPECT_FALSE(w.update(10, 0.0, 1e-4));
  EXPECT_TRUE(w.update(20, 0.0, 1e-4));
}

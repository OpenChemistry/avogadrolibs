/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// The parts of the command test harness that report through gtest. They live
// apart from commandtestharness.cpp so the in-process fuzz target can link
// the harness without gtest.

#include "commandtestharness.h"

#include <gtest/gtest.h>

namespace Avogadro::QtPluginsTests {

void reportLateSignals(const std::string& description)
{
  ADD_FAILURE() << description;
}

void recordKnownDeviation(const char* what)
{
  ::testing::Test::RecordProperty("known_deviation", what);
}

void recordUndecided(const char* what)
{
  ::testing::Test::RecordProperty("undecided", what);
}

bool expectNear(const Vector3& actual, const Vector3& expected,
                double tolerance, const std::string& what)
{
  const bool near = (actual - expected).cwiseAbs().maxCoeff() <= tolerance;
  EXPECT_TRUE(near) << what << ": got (" << actual.x() << ", " << actual.y()
                    << ", " << actual.z() << "), expected (" << expected.x()
                    << ", " << expected.y() << ", " << expected.z()
                    << ") within " << tolerance;
  return near;
}

} // namespace Avogadro::QtPluginsTests

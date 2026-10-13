/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

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

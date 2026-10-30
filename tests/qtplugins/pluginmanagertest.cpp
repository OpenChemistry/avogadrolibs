/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugintestutils.h"

#include <gtest/gtest.h>

using namespace Avogadro;
using namespace Avogadro::QtPluginsTests;

// The one thing every test built on the plugin manager relies on: it finds
// every kind of plugin.
TEST(PluginManagerTest, everyKindIsFound)
{
  EXPECT_FALSE(pluginIdentifiers<QtGui::ExtensionPluginFactory>().isEmpty());
  EXPECT_FALSE(pluginIdentifiers<QtGui::ScenePluginFactory>().isEmpty());
  EXPECT_FALSE(pluginIdentifiers<QtGui::ToolPluginFactory>().isEmpty());
  EXPECT_TRUE(pluginIdentifiers<QtGui::ToolPluginFactory>().contains(
    QStringLiteral("Navigator")));
}

TEST(PluginManagerTest, pluginFactoryUnknownIdIsNull)
{
  // Regression: PluginManager::pluginFactory() used to return the last
  // factory it looked at when no identifier matched.
  EXPECT_EQ(
    loadedPlugins().pluginFactory<QtGui::ToolPluginFactory>("NoSuchTool"),
    nullptr);
  EXPECT_EQ(
    loadedPlugins().pluginFactory<QtGui::ScenePluginFactory>("NoSuchScene"),
    nullptr);
  EXPECT_EQ(loadedPlugins().pluginFactory<QtGui::ExtensionPluginFactory>(""),
            nullptr);
  EXPECT_NE(loadedPlugins().pluginFactory<QtGui::ToolPluginFactory>("Editor"),
            nullptr);
  // A factory of the wrong kind is not a match either.
  EXPECT_EQ(loadedPlugins().pluginFactory<QtGui::ScenePluginFactory>("Editor"),
            nullptr);
}

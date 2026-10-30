/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "plugintestutils.h"

#include <QtCore/QTemporaryDir>

namespace Avogadro::QtPluginsTests {

QtPlugins::PluginManager& loadedPlugins()
{
  QtPlugins::PluginManager* manager = QtPlugins::PluginManager::instance();
  static const bool loaded = [manager] {
    // Static plugins only. load(dir) registers them whatever the directory,
    // and an empty one keeps an installed Avogadro's plugins out (QDir("")
    // would be the working directory).
    manager->pluginDirList().clear();
    const QTemporaryDir empty;
    manager->load(empty.path());
    return true;
  }();
  (void)loaded;
  return *manager;
}

} // namespace Avogadro::QtPluginsTests

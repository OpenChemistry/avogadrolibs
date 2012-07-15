/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "pluginmanager.h"

#include "sceneplugin.h"
#include "extensionplugin.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QMutex>
#include <QtCore/QPluginLoader>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>

namespace Avogadro {
namespace QtGui {

PluginManager::PluginManager(QObject *p) : QObject(p)
{
  m_relativeToApp = "/../lib/avogadro2/plugins";
#ifdef __APPLE__
  QString buildRelative("/../../../..");
  qDebug() << QCoreApplication::applicationDirPath() + buildRelative
              + "/CMakeCache.txt";
  if (QFileInfo(QCoreApplication::applicationDirPath() + buildRelative
                + "/CMakeCache.txt").exists()) {
    qDebug() << QCoreApplication::applicationDirPath()
                + buildRelative
                + "/lib/avogadro2/plugins";
    m_pluginDirs.append(QDir(QCoreApplication::applicationDirPath()
                             + buildRelative
                             + "/lib/avogadro2/plugins").absolutePath());
    qDebug() << QDir(QCoreApplication::applicationDirPath()
                     + buildRelative
                     + "/lib/avogadro2/plugins").absolutePath();
  }
#endif
  QDir dir(QCoreApplication::applicationDirPath() + m_relativeToApp);
  m_pluginDirs.append(dir.absolutePath());
}

PluginManager::~PluginManager()
{
}

PluginManager * PluginManager::instance()
{
  static QMutex mutex;
  // Compiler initializes this static pointer to 0.
  static PluginManager *pluginManagerInstance;
  if (!pluginManagerInstance) {
    mutex.lock();
    if (!pluginManagerInstance)
      pluginManagerInstance = new PluginManager(QCoreApplication::instance());
    mutex.unlock();
  }
  return pluginManagerInstance;
}

void PluginManager::load()
{
  foreach(const QString &dir, m_pluginDirs)
    load(dir);
}

void PluginManager::load(const QString &path)
{
  QDir dir(path);
  qDebug() << dir.entryList(QDir::Files);
  foreach(const QString &pluginPath, dir.entryList(QDir::Files)) {
    QPluginLoader pluginLoader(dir.absolutePath() + "/" + pluginPath);

    // We only want to count plugins once.
    if (pluginLoader.isLoaded())
      continue;

    QObject *pluginInstance = pluginLoader.instance();

    // Check if the plugin loaded correctly. Keep debug output for now, should
    // go away once we have verified this (or added to a logger).
    if (!pluginInstance) {
      qDebug() << "Failed to load" << pluginPath << "error"
               << pluginLoader.errorString();
    }
    else {
      qDebug() << "Loaded" << dir.absolutePath() + "/" + pluginPath << "->";
      pluginInstance->dumpObjectInfo();
    }

    m_plugins.append(pluginInstance);

    // Now attempt to cast to known factory types, and make it available.
    ScenePluginFactory *scenePluginFactory =
      qobject_cast<Avogadro::QtGui::ScenePluginFactory *>(pluginInstance);
    if (scenePluginFactory)
      m_scenePluginFactories.append(scenePluginFactory);

    ExtensionPluginFactory *extensionPluginFactory =
        qobject_cast<Avogadro::QtGui::ExtensionPluginFactory *>(pluginInstance);
    if (extensionPluginFactory)
      m_extensionPluginFactories.append(extensionPluginFactory);

    qDebug() << "Scene factories:" << m_scenePluginFactories.size() << scenePluginFactory;
    qDebug() << "Extension factories:" << m_extensionPluginFactories.size() << extensionPluginFactory;
  }
}

QList<ScenePluginFactory *> PluginManager::scenePluginFactories() const
{
  return m_scenePluginFactories;
}

QList<ExtensionPluginFactory *> PluginManager::extensionPluginFactories() const
{
  return m_extensionPluginFactories;
}

} // End QtGui namespace
} // End Avogadro namespace

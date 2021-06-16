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

#ifndef AVOGADRO_QTGUI_PLUGINMANAGER_H
#define AVOGADRO_QTGUI_PLUGINMANAGER_H

#include "avogadroqtpluginsexport.h"

#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QStringList>

namespace Avogadro {
namespace QtPlugins {

class ScenePluginFactory;
class ExtensionPluginFactory;

/**
 * @class PluginManager pluginmanager.h <avogadro/qtplugins/pluginmanager.h>
 * @brief This class takes care of finding and loading Avogadro plugins.
 * @author Marcus D. Hanwell
 *
 * This class will find and load Avogadro plugins. Once loaded you can use an
 * instance of this class to query and construct plugin instances. By default
 * plugins are loaded from
 * QApplication::applicationDirPath()../<libdir>/avogadro/plugins but this can
 * be changed, or more paths can be added.
 *
 * The load methods can be called multiple times, and will load any new plugins
 * while ignoring plugins that have already been loaded.
 */

class AVOGADROQTPLUGINS_EXPORT PluginManager : public QObject
{
  Q_OBJECT

public:
  /**
   * Get the singleton instance of the plugin manager. This instance should not
   * be deleted.
   */
  static PluginManager* instance();

  /**
   * Get a reference to the plugin directory path list. Modifying this before
   * calling load will allow you to add, remove or append to the search paths.
   */
  QStringList& pluginDirList() { return m_pluginDirs; }

  /** Load all plugins available in the specified plugin directories. */
  void load();
  void load(const QString& dir);

  /**
   * Let the user request plugins with a certain type, this must use the Qt
   * mechanisms as qobject_cast is used in conjunction with interfaces.
   *
   * @code
   * factory =
   * pluginManager->pluginFactories<Avogadro::QtGui::ScenePluginFactory>();
   * @endcode
   */
  template<typename T>
  QList<T*> pluginFactories() const;

  /**
   * Let the user request a plugin by name, this must use the Qt
   * mechanisms as qobject_cast is used in conjunction with interfaces.
   *
   * @code
     factory = pluginManager->
                 pluginFactories<Avogadro::QtGui::ScenePluginFactory>("name");
   * @endcode
   *
   * @param id The identifier of the plugin factory.
   * @return The plugin factory if the plugin was found, nullptr otherwise.
   */
  template<typename T>
  T* pluginFactory(const QString& id) const;

private:
  // Hide the constructor, destructor, copy and assignment operator.
  PluginManager(QObject* parent = nullptr);
  ~PluginManager() override;
  PluginManager(const PluginManager&);            // Not implemented.
  PluginManager& operator=(const PluginManager&); // Not implemented.

  QStringList m_pluginDirs;
  QString m_relativeToApp;

  bool m_staticPluginsLoaded;

  // Storage for the loaded plugin instances.
  QList<QObject*> m_plugins;
};

template<typename T>
QList<T*> PluginManager::pluginFactories() const
{
  QList<T*> factories;
  foreach (QObject* plugin, m_plugins) {
    T* factory = qobject_cast<T*>(plugin);
    if (factory)
      factories.append(factory);
  }
  return factories;
}

template<typename T>
T* PluginManager::pluginFactory(const QString& id) const
{
  T* factory;
  foreach (QObject* plugin, m_plugins) {
    factory = qobject_cast<T*>(plugin);
    if (factory && factory->identifier() == id)
      break;
  }
  return factory;
}

} // End QtPlugins namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTGUI_PLUGINMANAGER_H

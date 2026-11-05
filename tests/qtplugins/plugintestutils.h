/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_TESTS_PLUGINTESTUTILS_H
#define AVOGADRO_TESTS_PLUGINTESTUTILS_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/sceneplugin.h>
#include <avogadro/qtgui/toolplugin.h>
#include <avogadro/qtplugins/pluginmanager.h>

#include <QtCore/QString>
#include <QtCore/QStringList>

#include <memory>
#include <type_traits>
#include <utility>

namespace Avogadro::QtPluginsTests {

/**
 * The plugin manager with every in-tree static plugin loaded, as the
 * application sees it. Loaded on first use; needs a QApplication.
 */
QtPlugins::PluginManager& loadedPlugins();

/**
 * Whether main() could make an OpenGL context current. Rendering::TextLabel
 * constructors call OpenGL, so a test that makes a plugin build a text label
 * (drawing a tool's overlay, for instance) crashes without one: such tests
 * skip themselves instead. Some platforms never have one (Qt's offscreen
 * platform on macOS, and on Linux without a display server).
 */
bool haveGLContext();
void setHaveGLContext(bool have);

/** @return The identifiers of every factory of type @p Factory, sorted. */
template <typename Factory>
QStringList pluginIdentifiers()
{
  QStringList ids;
  for (Factory* factory : loadedPlugins().pluginFactories<Factory>())
    ids << factory->identifier();
  ids.sort();
  return ids;
}

/**
 * @return A new instance of the plugin @p id, owned by the caller, or null
 * if no factory of type @p Factory has that identifier.
 */
template <typename Factory>
auto createPlugin(const QString& id) -> std::unique_ptr<std::remove_pointer_t<
  decltype(std::declval<Factory&>().createInstance(nullptr))>>
{
  using Plugin =
    std::remove_pointer_t<decltype(std::declval<Factory&>().createInstance(
      nullptr))>;
  Factory* factory = loadedPlugins().pluginFactory<Factory>(id);
  if (factory == nullptr)
    return nullptr;
  return std::unique_ptr<Plugin>(factory->createInstance(nullptr));
}

inline std::unique_ptr<QtGui::ExtensionPlugin> createExtension(
  const QString& id)
{
  return createPlugin<QtGui::ExtensionPluginFactory>(id);
}

inline std::unique_ptr<QtGui::ScenePlugin> createScenePlugin(const QString& id)
{
  return createPlugin<QtGui::ScenePluginFactory>(id);
}

inline std::unique_ptr<QtGui::ToolPlugin> createTool(const QString& id)
{
  return createPlugin<QtGui::ToolPluginFactory>(id);
}

} // namespace Avogadro::QtPluginsTests

#endif // AVOGADRO_TESTS_PLUGINTESTUTILS_H

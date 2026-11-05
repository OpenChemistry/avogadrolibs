/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "extensionplugin.h"

#include "commandregistry.h"

#include <QWidget>

namespace Avogadro::QtGui {

ExtensionPlugin::ExtensionPlugin(QObject* parent_) : QObject(parent_) {}

ExtensionPlugin::~ExtensionPlugin() {}

void ExtensionPlugin::registerCommands()
{
  if (m_commandRegistry) {
    m_commandRegistry->announce(
      [this](const QString& name, const QString& description) {
        emit registerCommand(name, description);
      });
  }
}

QJsonObject ExtensionPlugin::commandSchema(const QString& command) const
{
  return m_commandRegistry ? m_commandRegistry->schema(command) : QJsonObject();
}

CommandRegistry& ExtensionPlugin::commandRegistry()
{
  if (!m_commandRegistry) {
    m_commandRegistry = std::make_unique<CommandRegistry>(
      [this](const QString& message) { emit commandFailed(message); });
  }
  return *m_commandRegistry;
}

QList<Io::FileFormat*> ExtensionPlugin::fileFormats() const
{
  return QList<Io::FileFormat*>();
}

QList<QDockWidget*> ExtensionPlugin::dockWidgets() const
{
  return QList<QDockWidget*>();
}

Qt::DockWidgetArea ExtensionPlugin::preferredDockArea(QDockWidget*) const
{
  return Qt::RightDockWidgetArea;
}

ExtensionPluginFactory::~ExtensionPluginFactory() {}

bool ExtensionPlugin::readMolecule(Molecule&)
{
  return false;
}

void ExtensionPlugin::setScene(Rendering::Scene*) {}

void ExtensionPlugin::setCamera([[maybe_unused]] Rendering::Camera* camera) {}

void ExtensionPlugin::setActiveWidget(QWidget* widget)
{
  setParent(widget);
}

bool ExtensionPlugin::handleCommand(const QString& command,
                                    const QVariantMap& options)
{
  Q_UNUSED(command);
  Q_UNUSED(options);
  return false;
}

} // namespace Avogadro::QtGui

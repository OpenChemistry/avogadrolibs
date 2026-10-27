/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "toolplugin.h"

#include "commandregistry.h"

namespace Avogadro::QtGui {

ToolPlugin::ToolPlugin(QObject* parent_) : QObject(parent_) {}

ToolPlugin::~ToolPlugin() {}

void ToolPlugin::registerCommands()
{
  if (m_commandRegistry) {
    m_commandRegistry->announce(
      [this](const QString& name, const QString& description) {
        emit registerCommand(name, description);
      });
  }
}

QJsonObject ToolPlugin::commandSchema(const QString& command) const
{
  return m_commandRegistry ? m_commandRegistry->schema(command) : QJsonObject();
}

CommandRegistry& ToolPlugin::commandRegistry()
{
  if (!m_commandRegistry) {
    m_commandRegistry = std::make_unique<CommandRegistry>(
      [this](const QString& message) { emit commandFailed(message); });
  }
  return *m_commandRegistry;
}

QUndoCommand* ToolPlugin::mousePressEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::mouseReleaseEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::mouseMoveEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::mouseDoubleClickEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::wheelEvent(QWheelEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::keyPressEvent(QKeyEvent*)
{
  return nullptr;
}

QUndoCommand* ToolPlugin::keyReleaseEvent(QKeyEvent*)
{
  return nullptr;
}

void ToolPlugin::draw(Rendering::GroupNode&) {}

bool ToolPlugin::handleCommand(const QString& command,
                               const QVariantMap& options)
{
  Q_UNUSED(command);
  Q_UNUSED(options);
  return false;
}

ToolPluginFactory::~ToolPluginFactory() {}

} // namespace Avogadro::QtGui

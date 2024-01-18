/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "toolplugin.h"
#include <QtGui/QPalette>

namespace Avogadro::QtGui {

ToolPlugin::ToolPlugin(QObject* parent_) : QObject(parent_) {}

ToolPlugin::~ToolPlugin() {}

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

// Method suggested by Qt to determine if theme is dark pre Qt6.5
static bool shouldApplyDarkFrame()
{
  const QPalette defaultPalette;
    return defaultPalette.color(QPalette::WindowText).lightness()
      > defaultPalette.color(QPalette::Window).lightness();
}

bool ToolPlugin::darkTheme = shouldApplyDarkFrame();

} // namespace Avogadro::QtGui

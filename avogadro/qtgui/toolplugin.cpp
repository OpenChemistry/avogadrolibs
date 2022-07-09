/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "toolplugin.h"

namespace Avogadro::QtGui {

ToolPlugin::ToolPlugin(QObject* parent_) : QObject(parent_)
{
}

ToolPlugin::~ToolPlugin()
{
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

void ToolPlugin::draw(Rendering::GroupNode&)
{
}

ToolPluginFactory::~ToolPluginFactory()
{
}

} // End Avogadro namespace

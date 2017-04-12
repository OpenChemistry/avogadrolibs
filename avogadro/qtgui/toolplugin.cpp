/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "toolplugin.h"

namespace Avogadro {
namespace QtGui {

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

} // End QtGui namespace
} // End Avogadro namespace

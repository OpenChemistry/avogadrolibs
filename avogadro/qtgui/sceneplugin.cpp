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

#include "sceneplugin.h"

namespace Avogadro {
namespace QtGui {

ScenePlugin::ScenePlugin(QObject* parent_) : QObject(parent_) {}

ScenePlugin::~ScenePlugin() {}

void ScenePlugin::process(const Core::Molecule& molecule,
                          Rendering::GroupNode& node)
{}

void ScenePlugin::process(const QtGui::Molecule& molecule,
                          Rendering::GroupNode& node)
{}

void ScenePlugin::processEditable(const RWMolecule&, Rendering::GroupNode&) {}

QWidget* ScenePlugin::setupWidget()
{
  return nullptr;
}

bool ScenePlugin::isEnabled() const
{
  return m_layerManager.isEnabled();
}

bool ScenePlugin::isActiveLayerEnabled() const
{
  return m_layerManager.isActiveLayerEnabled();
}

void ScenePlugin::setEnabled(bool enable)
{
  m_layerManager.setEnabled(enable);
}

} // namespace QtGui
} // namespace Avogadro

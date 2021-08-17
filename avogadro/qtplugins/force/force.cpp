/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "force.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/rendering/arrowgeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDoubleSpinBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtPlugins {

using Core::Array;
using Core::Elements;
using Core::Molecule;
using Rendering::ArrowGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

Force::Force(QObject* p) : ScenePlugin(p), m_enabled(false) {}

Force::~Force() {}

void Force::process(const Molecule& molecule, Rendering::GroupNode& node)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  ArrowGeometry* arrows = new ArrowGeometry;
  arrows->identifier().molecule = &molecule;
  geometry->addDrawable(arrows);
  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom1 = molecule.atom(i);
    Vector3f pos1 = atom1.position3d().cast<float>();
    Vector3f forceVector = atom1.forceVector().cast<float>();
    arrows->addSingleArrow(pos1, pos1 + forceVector);
  }
}

bool Force::isEnabled() const
{
  return m_enabled;
}

bool Force::isActiveLayerEnabled() const
{
  return m_enabled;
}

void Force::setEnabled(bool enable)
{
  m_enabled = enable;
}
} // namespace QtPlugins
} // namespace Avogadro

/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.
  Copyright 2013 Tim Vandermeersch <tim.vandermeersch@gmail.com>

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "vanderwaalsao.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/rendering/ambientocclusionspheregeometry.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using QtGui::PluginLayerManager;
using Rendering::AmbientOcclusionSphereGeometry;
using Rendering::GeometryNode;
using Rendering::GroupNode;

VanDerWaalsAO::VanDerWaalsAO(QObject* p) : ScenePlugin(p)
{
  m_layerManager = PluginLayerManager(m_name);
}

VanDerWaalsAO::~VanDerWaalsAO() {}

void VanDerWaalsAO::process(const QtGui::Molecule& molecule,
                            Rendering::GroupNode& node)
{
  // Add a sphere node to contain all of the VdW spheres.
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);
  AmbientOcclusionSphereGeometry* spheres = new AmbientOcclusionSphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    if (!m_layerManager.atomEnabled(i)) {
      continue;
    }
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char* c = Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    spheres->addSphere(atom.position3d().cast<float>(), color,
                       static_cast<float>(Elements::radiusVDW(atomicNumber)),
                       i);
  }
}

} // namespace QtPlugins
} // namespace Avogadro

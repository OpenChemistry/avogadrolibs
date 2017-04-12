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

#include "vanderwaals.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;

VanDerWaals::VanDerWaals(QObject* p) : ScenePlugin(p), m_enabled(false)
{
}

VanDerWaals::~VanDerWaals()
{
}

void VanDerWaals::process(const Core::Molecule& molecule,
                          Rendering::GroupNode& node)
{
  // Add a sphere node to contain all of the VdW spheres.
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);
  SphereGeometry* spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  for (Index i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char* c = Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    spheres->addSphere(atom.position3d().cast<float>(), color,
                       static_cast<float>(Elements::radiusVDW(atomicNumber)));
  }
}

bool VanDerWaals::isEnabled() const
{
  return m_enabled;
}

void VanDerWaals::setEnabled(bool enable)
{
  m_enabled = enable;
}
}
}

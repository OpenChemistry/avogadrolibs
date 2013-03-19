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

#include "ballandstick.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/elements.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/cylindergeometry.h>

namespace Avogadro {
namespace QtPlugins {

using Core::Elements;
using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::SphereGeometry;
using Rendering::CylinderGeometry;

BallAndStick::BallAndStick(QObject *p) : ScenePlugin(p), m_enabled(true)
{
}

BallAndStick::~BallAndStick()
{
}

void BallAndStick::process(const Molecule &molecule,
                           Rendering::GroupNode &node)
{
  // Add a sphere node to contain all of the spheres.
  GeometryNode *geometry = new GeometryNode;
  node.addChild(geometry);
  SphereGeometry *spheres = new SphereGeometry;
  spheres->identifier().molecule = &molecule;
  spheres->identifier().type = Rendering::AtomType;
  geometry->addDrawable(spheres);

  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char *c = Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    spheres->addSphere(atom.position3d().cast<float>(), color,
                       static_cast<float>(Elements::radiusVDW(atomicNumber))
                       * 0.3);
  }

  float bondRadius = 0.1f;
  Vector3ub bondColor(127, 127, 127);
  CylinderGeometry *cylinders = new CylinderGeometry;
  cylinders->identifier().molecule = &molecule;
  cylinders->identifier().type = Rendering::BondType;
  geometry->addDrawable(cylinders);
  for (size_t i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
    bondVector /= bondLength;
    switch (bond.order()) {
    case 3: {
      Vector3f delta = bondVector.unitOrthogonal() * (2.0f * bondRadius);
      cylinders->addCylinder(pos1 + delta, bondVector, bondLength, bondRadius,
                             bondColor, i);
      cylinders->addCylinder(pos1 - delta, bondVector, bondLength, bondRadius,
                             bondColor, i);
    }
    default:
    case 1:
      cylinders->addCylinder(pos1, bondVector, bondLength, bondRadius,
                             bondColor, i);
      break;
    case 2: {
      Vector3f delta = bondVector.unitOrthogonal() * bondRadius;
      cylinders->addCylinder(pos1 + delta, bondVector, bondLength, bondRadius,
                             bondColor, i);
      cylinders->addCylinder(pos1 - delta, bondVector, bondLength, bondRadius,
                             bondColor, i);
    }
    }
  }
}

bool BallAndStick::isEnabled() const
{
  return m_enabled;
}

void BallAndStick::setEnabled(bool enable)
{
  m_enabled = enable;
}

}
}

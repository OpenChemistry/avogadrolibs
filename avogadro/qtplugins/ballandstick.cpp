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
#include <avogadro/rendering/scene.h>

#include <QtCore/QtPlugin>

using Avogadro::Core::Molecule;
using Avogadro::Rendering::Scene;

namespace Avogadro {
namespace QtPlugins {

BallAndStick::BallAndStick(QObject *p) : ScenePlugin(p), m_enabled(false)
{
}

BallAndStick::~BallAndStick()
{
}

void BallAndStick::process(const Molecule &molecule, Scene &scene)
{
  Rendering::Primitive::Identifier identifier;
  identifier.molecule = &molecule;
  identifier.type = Rendering::Primitive::Atom;
  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    identifier.index = i;
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char *c = Core::Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    scene.addSphere(atom.position3d().cast<float>(), color,
                    static_cast<float>(Core::Elements::radiusVDW(
                                         atomicNumber) * 0.3),
                    identifier);
  }

  float bondRadius;
  Vector3ub bondColor(0.5, 0.5, 0.5);
  identifier.type = Rendering::Primitive::Bond;
  for (size_t i = 0; i < molecule.bondCount(); ++i) {
    Core::Bond bond = molecule.bond(i);
    identifier.index = i;
    /// @todo multicylinders for bond orders
    Vector3f pos1 = bond.atom1().position3d().cast<float>();
    Vector3f pos2 = bond.atom2().position3d().cast<float>();
    Vector3f bondVector = pos2 - pos1;
    float bondLength = bondVector.norm();
//    scene.addCylinder(pos1, bondVector.normalized(), bondLength, color,
//                      bondRadius, identifier);
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

Q_EXPORT_PLUGIN2(ballandstick, Avogadro::QtPlugins::BallAndStickFactory)

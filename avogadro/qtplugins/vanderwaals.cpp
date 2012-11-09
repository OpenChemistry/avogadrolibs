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

#include <avogadro/core/molecule.h>
#include <avogadro/core/elements.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QtPlugin>

namespace Avogadro {
namespace QtPlugins {

VanDerWaals::VanDerWaals(QObject *p) : ScenePlugin(p), m_enabled(false)
{
}

VanDerWaals::~VanDerWaals()
{
}

void VanDerWaals::process(const Core::Molecule &molecule,
                          Rendering::Scene &scene)
{
  Rendering::Scene::PrimitiveIdentifier identifier;
  identifier.molecule = &molecule;
  identifier.type = Rendering::Scene::AtomPrimitive;
  for (size_t i = 0; i < molecule.atomCount(); ++i) {
    Core::Atom atom = molecule.atom(i);
    identifier.index = i;
    unsigned char atomicNumber = atom.atomicNumber();
    const unsigned char *c = Core::Elements::color(atomicNumber);
    Vector3ub color(c[0], c[1], c[2]);
    scene.addSphere(atom.position3d().cast<float>(), color,
                    static_cast<float>(Core::Elements::radiusVDW(atomicNumber)),
                    identifier);
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

Q_EXPORT_PLUGIN2(vanderwaals, Avogadro::QtPlugins::VanDerWaalsFactory)

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

#include "meshes.h"

#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/mesh.h>
#include <avogadro/core/elements.h>
#include <avogadro/rendering/scene.h>

#include <QtCore/QDebug>

using Avogadro::Core::Molecule;
using Avogadro::Rendering::Scene;

namespace Avogadro {
namespace QtPlugins {

Meshes::Meshes(QObject *p) : ScenePlugin(p), m_enabled(false)
{
}

Meshes::~Meshes()
{
}

void Meshes::process(const Molecule &molecule, Scene &scene)
{
  const QtGui::Molecule *mol = dynamic_cast<const QtGui::Molecule*>(&molecule);
  if (mol) {
    qDebug() << "Success!!!";
    if (mol->meshCount()) {
      qDebug() << "We have" << mol->meshCount() << "meshes...";
      const QtGui::Mesh *mesh = mol->mesh(0);
      qDebug() << mesh << "with" << mesh->numVertices() << "vertices";
      size_t n = mesh->numVertices();
      scene.addTriangles(static_cast<const Vector3f *>(mesh->vertex(0)),
                         static_cast<const Vector3f *>(mesh->normal(0)), n);
    }
  }
}

bool Meshes::isEnabled() const
{
  return m_enabled;
}

void Meshes::setEnabled(bool enable)
{
  m_enabled = enable;
}

}
}

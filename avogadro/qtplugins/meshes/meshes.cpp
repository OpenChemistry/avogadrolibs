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
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshnode.h>

#include <QtCore/QDebug>

namespace Avogadro {
namespace QtPlugins {

using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::MeshNode;

Meshes::Meshes(QObject *p) : ScenePlugin(p), m_enabled(false)
{
}

Meshes::~Meshes()
{
}

void Meshes::process(const Molecule &molecule, GroupNode &node)
{
  const QtGui::Molecule *mol = dynamic_cast<const QtGui::Molecule*>(&molecule);

  // Add a sphere node to contain all of the VdW spheres.
  // Add a sphere node to contain all of the VdW spheres.
  GeometryNode *geometry = new GeometryNode;
  node.addChild(geometry);

  unsigned char opacity = 100;

  if (mol) {
    if (mol->meshCount()) {
      qDebug() << "We have" << mol->meshCount() << "meshes...";
      const QtGui::Mesh *mesh = mol->mesh(0);
      qDebug() << mesh << "with" << mesh->numVertices() << "vertices";
      size_t n = mesh->numVertices();

      MeshNode *mesh1 = new MeshNode;
      geometry->addDrawable(mesh1);
      mesh1->addTriangles(static_cast<const Vector3f *>(mesh->vertex(0)),
                          static_cast<const Vector3f *>(mesh->normal(0)),
                          NULL, n);
      mesh1->setColor(Vector3ub(255, 0, 0));
      mesh1->setOpacity(opacity);

      if (mol->meshCount() >= 2) {
        MeshNode *mesh2 = new MeshNode;
        geometry->addDrawable(mesh2);
        mesh = mol->mesh(1);
        n = mesh->numVertices();
        mesh2->addTriangles(static_cast<const Vector3f *>(mesh->vertex(0)),
                            static_cast<const Vector3f *>(mesh->normal(0)),
                            NULL, n);
        mesh2->setColor(Vector3ub(0, 0, 255));
        mesh2->setOpacity(opacity);
      }
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

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

#include <avogadro/core/array.h>
#include <avogadro/core/mesh.h>
#include <avogadro/core/molecule.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>

#include <QtCore/QDebug>

#include <algorithm>

namespace Avogadro {
namespace QtPlugins {

using Core::Mesh;
using Core::Molecule;
using Rendering::GeometryNode;
using Rendering::GroupNode;
using Rendering::MeshGeometry;

Meshes::Meshes(QObject* p) : ScenePlugin(p), m_enabled(true) {}

Meshes::~Meshes() {}

// Generator for std::generate call below:
namespace {
struct Sequence
{
  Sequence() : i(0) {}
  unsigned int operator()() { return i++; }
  void reset() { i = 0; }
  unsigned int i;
};
} // namespace

void Meshes::process(const Molecule& mol, GroupNode& node)
{
  GeometryNode* geometry = new GeometryNode;
  node.addChild(geometry);

  unsigned char opacity = 150;

  if (mol.meshCount()) {
    const Mesh* mesh = mol.mesh(0);

    /// @todo Allow use of MeshGeometry without an index array when all vertices
    /// form explicit triangles.
    // Create index array:
    Sequence indexGenerator;
    Core::Array<unsigned int> indices(mesh->numVertices());
    std::generate(indices.begin(), indices.end(), indexGenerator);

    MeshGeometry* mesh1 = new MeshGeometry;
    geometry->addDrawable(mesh1);
    mesh1->setColor(Vector3ub(255, 0, 0));
    mesh1->setOpacity(opacity);
    mesh1->addVertices(mesh->vertices(), mesh->normals());
    mesh1->addTriangles(indices);
    mesh1->setRenderPass(opacity == 255 ? Rendering::OpaquePass
                                        : Rendering::TranslucentPass);

    if (mol.meshCount() >= 2) {
      MeshGeometry* mesh2 = new MeshGeometry;
      geometry->addDrawable(mesh2);
      mesh = mol.mesh(1);
      if (mesh->numVertices() < indices.size()) {
        indices.resize(mesh->numVertices());
      } else if (mesh->numVertices() > indices.size()) {
        indexGenerator.reset();
        indices.resize(mesh->numVertices());
        std::generate(indices.begin(), indices.end(), indexGenerator);
      }
      mesh2->setColor(Vector3ub(0, 0, 255));
      mesh2->setOpacity(opacity);
      mesh2->addVertices(mesh->vertices(), mesh->normals());
      mesh2->addTriangles(indices);
      mesh2->setRenderPass(opacity == 255 ? Rendering::OpaquePass
                                          : Rendering::TranslucentPass);
    }
  }
}

bool Meshes::isEnabled() const
{
  return m_enabled;
}

bool Meshes::isActiveLayerEnabled() const
{
  return m_enabled;
}

void Meshes::setEnabled(bool enable)
{
  m_enabled = enable;
}
} // namespace QtPlugins
} // namespace Avogadro

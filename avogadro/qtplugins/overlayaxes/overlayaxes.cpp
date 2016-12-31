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

#include "overlayaxes.h"

#include <avogadro/rendering/avogadrogl.h>
#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/meshgeometry.h>

#include <avogadro/core/array.h>
#include <avogadro/core/vector.h>

#include <Eigen/Geometry>

using Avogadro::Core::Array;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GroupNode;
using Avogadro::Rendering::MeshGeometry;
using Avogadro::Vector3f;
using Eigen::Affine3f;

namespace {
const static float M_PI_F = 3.14159265358979323846f;

// Mesh class that overrides the camera used in rendering.
class CustomMesh : public MeshGeometry
{
public:
  CustomMesh() { setRenderPass(Avogadro::Rendering::Overlay3DPass); }
  ~CustomMesh() override {}

  void render(const Camera &camera) override;
};

void CustomMesh::render(const Camera &camera)
{
  // Swap in a new viewport/camera for the overlay
  /// @todo This is messy, it would be better to specify camera/viewport in a
  /// group/geometry node that the renderer could apply to all children.

  // Keep the rotation, lose the translation:
  Affine3f mv(camera.modelView());
  mv.matrix().block<3, 1>(0, 3) = Vector3f::Zero();

  // The largest window dimension, used to scale the axes
  const int maxDim = std::max(camera.width(), camera.height());

  Camera meshCamera(camera);
  meshCamera.setViewport(maxDim / 10, maxDim / 10);
  meshCamera.setModelView(mv);
  meshCamera.calculateOrthographic(-1.f, 1.f, -1.f, 1.f, -1.f, 1.f);

  glViewport(static_cast<GLint>(10),
             static_cast<GLsizei>(10),
             static_cast<GLint>(meshCamera.width()),
             static_cast<GLsizei>(meshCamera.height()));

  MeshGeometry::render(meshCamera);

  glViewport(static_cast<GLint>(0),
             static_cast<GLsizei>(0),
             static_cast<GLint>(camera.width()),
             static_cast<GLsizei>(camera.height()));
}
} // end anon namespace

namespace Avogadro {
namespace QtPlugins {

class OverlayAxes::RenderImpl
{
public:
  RenderImpl();
  ~RenderImpl();

  CustomMesh *mesh;

private:
  void buildMesh();
  // axis must be normalized:
  void addAxis(const Vector3f &axis, const Vector3ub &color);
};

OverlayAxes::RenderImpl::RenderImpl()
  : mesh(new CustomMesh)
{
  buildMesh();
}

OverlayAxes::RenderImpl::~RenderImpl()
{
  delete mesh;
}

void OverlayAxes::RenderImpl::buildMesh()
{
  addAxis(Vector3f(1.f, 0.f, 0.f), Vector3ub(255, 0, 0));
  addAxis(Vector3f(0.f, 1.f, 0.f), Vector3ub(0, 255, 0));
  addAxis(Vector3f(0.f, 0.f, 1.f), Vector3ub(0, 0, 255));
}

void OverlayAxes::RenderImpl::addAxis(const Vector3f &axis,
                                      const Vector3ub &color)
{
  mesh->setColor(color);

  // Number of angular samples:
  const unsigned int res = 12;
  const float resf = static_cast<float>(res);
  // Cylinder length:
  const float cylLength = .75f;
  // Cylinder radius:
  const float cylRadius = 0.0625f;
  // Cone length:
  const float coneLength = .25f;
  // Cone radius:
  const float coneRadius = .125f;

  // Some vectors that will simplify things later:
  const Vector3f origin(0.f, 0.f, 0.f);
  const Vector3f cylVector(axis * cylLength);
  const Vector3f coneVector(axis * coneLength);
  const Vector3f axisVector(coneVector + cylVector);
  const Vector3f radialUnit(axis.unitOrthogonal());

  // Index offsets:
  const unsigned int coneBaseOffset = 0;
  const unsigned int coneBaseRadialsOffset = coneBaseOffset + 1;
  const unsigned int coneSideRadialsOffset = coneBaseRadialsOffset + res;
  const unsigned int coneTipsOffset = coneSideRadialsOffset + res;
  const unsigned int cylBaseRadialsOffset = coneTipsOffset + res;
  const unsigned int cylTopRadialsOffset = cylBaseRadialsOffset + res;
  const unsigned int numVertices = cylTopRadialsOffset + res;

  // Allocate arrays:
  Array<Vector3f> vertices(numVertices);
  Array<Vector3f> normals(numVertices);

  // This point doesn't change:
  vertices[coneBaseOffset] = origin + cylVector;
  normals[coneBaseOffset] = -axis;

  // Initial radial:
  Vector3f radial(radialUnit);

  // Create radial transform:
  Eigen::Affine3f xform(Eigen::AngleAxisf(2.f * M_PI_F / resf, axis));

  // Build vertex list:
  const Vector3f coneTip(origin + axisVector);
  Vector3f coneRadial;
  Vector3f coneSideNormal;
  Vector3f cylRadial;
  for (unsigned int i = 0; i < res; ++i) {
    coneRadial = origin + cylVector + (radial * coneRadius);
    // Calculating the cone side normal:
    //
    //       /|  (z points out of screen)  z = coneVector x coneRadial
    //      / |                            a = coneVector - coneRadial
    //  a  /  | coneVector                 n = z x a
    //    /   |
    //   /    |     (n is the normal for vector a)
    //  /_____|
    //    coneRadial
    coneSideNormal = -(coneVector.cross(coneRadial))
        .cross(coneVector - coneRadial).normalized();

    vertices[coneBaseRadialsOffset + i] = coneRadial;
    normals[coneBaseRadialsOffset + i] = -axis;

    vertices[coneSideRadialsOffset + i] = coneRadial;
    normals[coneSideRadialsOffset + i] = coneSideNormal;

    cylRadial = origin + (radial * cylRadius);
    vertices[cylBaseRadialsOffset + i] = cylRadial;
    normals[cylBaseRadialsOffset + i] = radial;

    vertices[cylTopRadialsOffset + i] = cylVector + cylRadial;
    normals[cylTopRadialsOffset + i] = radial;

    radial = xform * radial;
  }

  // Cone tip normals are averages of the side radial normals:
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int ind1 = coneSideRadialsOffset + i;
    unsigned int ind2 = coneSideRadialsOffset + ((i + 1) % res);
    vertices[coneTipsOffset + i] = coneTip;
    normals[coneTipsOffset + i] = (normals[ind1] + normals[ind2]).normalized();
  }

  // Add the vertices and get our index offset:
  const unsigned int baseOffset = mesh->addVertices(vertices, normals);

  // Stitch the vertices together:
  Array<unsigned int> triangles(3 * 4 * res); // 3 verts * 4 tri * nsamples
  unsigned int *ptr = triangles.data();
  for (unsigned int i = 0; i < res; ++i) {
    unsigned int i2 = (i + 1) % res;
    // Cone sides:
    *ptr++ = baseOffset + coneTipsOffset + i;
    *ptr++ = baseOffset + coneSideRadialsOffset + i;
    *ptr++ = baseOffset + coneSideRadialsOffset + i2;

    // Cone base:
    *ptr++ = baseOffset + coneBaseRadialsOffset + i;
    *ptr++ = baseOffset + coneBaseOffset;
    *ptr++ = baseOffset + coneBaseRadialsOffset + i2;

    // Cylinder side quad:
    *ptr++ = baseOffset + cylTopRadialsOffset + i;
    *ptr++ = baseOffset + cylBaseRadialsOffset + i;
    *ptr++ = baseOffset + cylTopRadialsOffset + i2;

    *ptr++ = baseOffset + cylBaseRadialsOffset + i;
    *ptr++ = baseOffset + cylTopRadialsOffset + i2;
    *ptr++ = baseOffset + cylBaseRadialsOffset + i2;
  }

  // Add the indices to the mesh
  mesh->addTriangles(triangles);
}

OverlayAxes::OverlayAxes(QObject *p)
  : ScenePlugin(p),
    m_enabled(true),
    m_render(new RenderImpl)
{
}

OverlayAxes::~OverlayAxes()
{
  delete m_render;
}

void OverlayAxes::process(const Core::Molecule &, Rendering::GroupNode &node)
{
  GeometryNode *geo = new GeometryNode;
  // Since our geometry doesn't change, we just make a copy of the pre-built
  // set of axes.
  geo->addDrawable(new CustomMesh(*m_render->mesh));
  node.addChild(geo);
}

void OverlayAxes::processEditable(const QtGui::RWMolecule &,
                                  Rendering::GroupNode &node)
{
  GeometryNode *geo = new GeometryNode;
  // Since our geometry doesn't change, we just make a copy of the pre-built
  // set of axes.
  geo->addDrawable(new CustomMesh(*m_render->mesh));
  node.addChild(geo);
}


bool OverlayAxes::isEnabled() const
{
  return m_enabled;
}

void OverlayAxes::setEnabled(bool enable)
{
  m_enabled = enable;
}

}
}

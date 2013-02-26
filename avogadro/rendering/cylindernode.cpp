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

#include "cylindernode.h"

#include "camera.h"
#include "scene.h"

#include "bufferobject.h"

#include "shader.h"
#include "shaderprogram.h"

namespace {
#include "cylinders_vs.h"
#include "cylinders_fs.h"
}

#include "avogadrogl.h"

#include <avogadro/core/matrix.h>

#include <iostream>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class CylinderNode::Private
{
public:
  Private() { }

  BufferObject vbo;
  BufferObject ibo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;

  size_t numberOfVertices;
  size_t numberOfIndices;
};

CylinderNode::CylinderNode() : m_dirty(false), d(new Private)
{
}

CylinderNode::~CylinderNode()
{
  delete d;
}

void CylinderNode::update()
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    cout << "building array buffers...\n";

    // Set some defaults for our cylinders.
    const unsigned int resolution = 12; // points per circle
    const float resolutionRadians =
        2.0 * static_cast<float>(M_PI) / static_cast<float>(resolution);
    std::vector<Vector3f> radials;
    radials.reserve(resolution);

    std::vector<unsigned int> cylinderIndices;
    std::vector<ColorNormalVertex> cylinderVertices;
    //cylinderIndices.reserve(m_indices.size() * 4);
    //cylinderVertices.reserve(m_cylinders.size() * 4);

    std::vector<size_t>::const_iterator itIndex = m_indices.begin();
    std::vector<CylinderColor>::const_iterator itCylinder = m_cylinders.begin();

    for (unsigned int i = 0;
         itIndex != m_indices.end(), itCylinder != m_cylinders.end();
         ++i, ++itIndex, ++itCylinder) {

      const Vector3f &position1 = itCylinder->position;
      const Vector3f &direction = itCylinder->direction;
      float radius = itCylinder->radius;

      const Vector3f position2 = position1 + direction
                                 * itCylinder->length;

      // Generate the radial vectors
      Vector3f radial = direction.unitOrthogonal() * radius;
      Eigen::AngleAxisf transform(resolutionRadians, direction);
      radials.clear();
      for (unsigned int i = 0; i < resolution; ++i) {
        radials.push_back(radial);
        radial = transform * radial;
      }

      // Cylinder
      ColorNormalVertex vert(itCylinder->color, -direction, position1);
      const unsigned int tubeStart =
          static_cast<unsigned int>(cylinderVertices.size());
      for (std::vector<Vector3f>::const_iterator it = radials.begin(),
           itEnd = radials.end(); it != itEnd; ++it) {
        vert.normal = *it;
        vert.vertex = position1 + *it;
        cylinderVertices.push_back(vert);
        vert.vertex = position2 + *it;
        cylinderVertices.push_back(vert);
      }
      // Now to stitch it together.
      for (unsigned int i = 0; i < resolution; ++i) {
        unsigned int r1 = i + i;
        unsigned int r2 = (i != 0 ? r1 : resolution + resolution) - 2;
        cylinderIndices.push_back(tubeStart + r1);
        cylinderIndices.push_back(tubeStart + r1 + 1);
        cylinderIndices.push_back(tubeStart + r2);

        cylinderIndices.push_back(tubeStart + r2);
        cylinderIndices.push_back(tubeStart + r1 + 1);
        cylinderIndices.push_back(tubeStart + r2 + 1);
      }
    }

    d->vbo.upload(cylinderVertices);
    d->ibo.upload(cylinderIndices);
    d->numberOfVertices = cylinderVertices.size();
    d->numberOfIndices = cylinderIndices.size();

    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(cylinders_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(cylinders_fs);
    if (!d->vertexShader.compile())
      cout << d->vertexShader.error() << endl;
    if (!d->fragmentShader.compile())
      cout << d->fragmentShader.error() << endl;
    d->program.attachShader(d->vertexShader);
    d->program.attachShader(d->fragmentShader);
    if (!d->program.link())
      cout << d->program.error() << endl;
  }
}

void CylinderNode::render(const Camera &camera)
{
  if (m_indices.empty() || m_cylinders.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  if (!d->program.bind())
    cout << d->program.error() << endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!d->program.enableAttributeArray("vertex"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("vertex",
                                    ColorNormalVertex::vertexOffset(),
                                    Vector3f())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color",
                                    ColorNormalVertex::colorOffset(),
                                    Vector3ub())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("normal"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("normal",
                                    ColorNormalVertex::normalOffset(),
                                    Vector3f())) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView",
                                  camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection",
                                  camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }
  Matrix3f normalMatrix =
      camera.modelView().linear().inverse().transpose();
  if (!d->program.setUniformValue("normalMatrix", normalMatrix))
    std::cout << d->program.error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices),
                      static_cast<GLsizei>(d->numberOfIndices),
                      GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid *>(NULL));

  d->vbo.release();
  d->ibo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");
  d->program.disableAttributeArray("texCoordinates");

  d->program.release();
}

void CylinderNode::addCylinder(const Vector3f &position,
                               const Vector3f &direction,
                               float length, float radius,
                               const Vector3ub &color)
{
  m_dirty = true;
  m_cylinders.push_back(CylinderColor(position, direction, length, radius,
                                      color));
  m_indices.push_back(m_indices.size());
}

void CylinderNode::clear()
{
  m_cylinders.clear();
  m_indices.clear();
}

} // End namespace Rendering
} // End namespace Avogadro

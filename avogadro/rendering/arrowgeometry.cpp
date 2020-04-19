/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "arrowgeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <iostream>
#include <limits>

namespace {
#include "arrow_vs.h"
}

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class ArrowGeometry::Private
{
public:
  Private() {}

  Shader vertexShader;
  ShaderProgram program;
};

ArrowGeometry::ArrowGeometry() : m_dirty(false), d(new Private) {}

ArrowGeometry::ArrowGeometry(const ArrowGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices),
    m_lineStarts(other.m_lineStarts), m_dirty(true), d(new Private)
{}

ArrowGeometry::~ArrowGeometry()
{
  delete d;
}

void ArrowGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void ArrowGeometry::update()
{
  if (m_vertices.empty())
    return;

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(arrow_vs);
    if (!d->vertexShader.compile())
      cout << d->vertexShader.error() << endl;
    d->program.attachShader(d->vertexShader);
    if (!d->program.link())
      cout << d->program.error() << endl;
  }
}

void ArrowGeometry::render(const Camera& camera)
{
  if (m_vertices.empty())
    return;

  // Prepare the shader program if necessary.
  update();

  if (!d->program.bind())
    cout << d->program.error() << endl;

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView", camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection", camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }

  // Render the arrows using the shader.
  for (unsigned int startIndex = 0; startIndex < m_vertices.size();
       ++startIndex) {
    Vector3f v3 =
      m_vertices[startIndex].first +
      0.8 * (m_vertices[startIndex].second - m_vertices[startIndex].first);
    drawLine(m_vertices[startIndex].first, v3, 2);
    drawCone(v3, m_vertices[startIndex].second, 0.05, 1.0);
  }

  d->program.release();
}

void ArrowGeometry::clear()
{
  m_vertices.clear();
  m_lineStarts.clear();
  m_dirty = true;
}

void ArrowGeometry::drawLine(const Vector3f& start, const Vector3f& end,
                             double lineWidth)
{
  // Draw a line between two points of the specified thickness

  glPushAttrib(GL_LIGHTING_BIT);
  glDisable(GL_LIGHTING);

  glLineWidth(lineWidth);

  // Draw the line
  glBegin(GL_LINE_STRIP);
  glVertex3fv(start.data());
  glVertex3fv(end.data());
  glEnd();

  glPopAttrib();
}

void ArrowGeometry::drawCone(const Vector3f& base, const Vector3f& cap,
                             double baseRadius, double)
{
  const int CONE_TESS_LEVEL = 30;
  // This draws a cone which will be most useful for drawing arrows etc.
  Vector3f axis = cap - base;
  Vector3f axisNormalized = axis.normalized();
  Vector3f ortho1, ortho2;
  ortho1 = axisNormalized.unitOrthogonal();
  ortho1 *= baseRadius;
  ortho2 = axisNormalized.cross(ortho1);

  // Draw the cone
  // unfortunately we can't use a GL_TRIANGLE_FAN because this would force
  // having a common normal vector at the tip.
  for (int j = 0; j < CONE_TESS_LEVEL; j++) {
    const double alphaStep = 2.0 * M_PI / CONE_TESS_LEVEL;
    double alpha = j * alphaStep;
    double alphaNext = alpha + alphaStep;
    double alphaPrec = alpha - alphaStep;
    Vector3f v = sin(alpha) * ortho1 + cos(alpha) * ortho2 + base;
    Vector3f vNext = sin(alphaNext) * ortho1 + cos(alphaNext) * ortho2 + base;
    Vector3f vPrec = sin(alphaPrec) * ortho1 + cos(alphaPrec) * ortho2 + base;
    Vector3f n = (cap - v).cross(v - vPrec).normalized();
    Vector3f nNext = (cap - vNext).cross(vNext - v).normalized();
    glBegin(GL_TRIANGLES);
    glColor3ub(0, 255, 0);
    glNormal3fv((n + nNext).normalized().data());
    glVertex3fv(cap.data());
    glNormal3fv(nNext.data());
    glVertex3fv(vNext.data());
    glNormal3fv(n.data());
    glVertex3fv(v.data());
    glEnd();
  }

  // Now to draw the base
  glBegin(GL_TRIANGLE_FAN);
  glNormal3fv((-axisNormalized).eval().data());
  glVertex3fv(base.data());
  for (int j = 0; j <= CONE_TESS_LEVEL; j++) {
    double alpha = -j * M_PI / (CONE_TESS_LEVEL / 2.0);
    Vector3f v = cos(alpha) * ortho1 + sin(alpha) * ortho2 + base;
    glVertex3fv(v.data());
  }
  glEnd();
}

void ArrowGeometry::addSingleArrow(const Vector3f& pos1, const Vector3f& pos2)
{
  m_vertices.reserve(m_vertices.size() + 1);
  m_vertices.push_back(std::pair<Vector3f, Vector3f>(pos1, pos2));

  m_dirty = true;
}

} // End namespace Rendering
} // End namespace Avogadro

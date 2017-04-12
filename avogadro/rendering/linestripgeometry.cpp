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

#include "linestripgeometry.h"

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
#include "linestrip_fs.h"
#include "linestrip_vs.h"
}

using Avogadro::Core::Array;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

const size_t LineStripGeometry::InvalidIndex =
  std::numeric_limits<size_t>::max();

class LineStripGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;
};

LineStripGeometry::LineStripGeometry()
  : m_color(255, 0, 0), m_opacity(255), m_dirty(false), d(new Private)
{
}

LineStripGeometry::LineStripGeometry(const LineStripGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices),
    m_lineStarts(other.m_lineStarts), m_lineWidths(other.m_lineWidths),
    m_color(other.m_color), m_opacity(other.m_opacity), m_dirty(true),
    d(new Private)
{
}

LineStripGeometry::~LineStripGeometry()
{
  delete d;
}

void LineStripGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void LineStripGeometry::update()
{
  if (m_vertices.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);
    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(linestrip_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(linestrip_fs);
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

void LineStripGeometry::render(const Camera& camera)
{
  if (m_vertices.empty() || m_lineStarts.empty() ||
      m_lineWidths.size() != m_lineStarts.size())
    return;

  // Prepare the VBO and shader program if necessary.
  update();

  if (!d->program.bind())
    cout << d->program.error() << endl;

  d->vbo.bind();

  // Set up our attribute arrays.
  if (!d->program.enableAttributeArray("vertex"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("vertex", PackedVertex::vertexOffset(),
                                    sizeof(PackedVertex), FloatType, 3,
                                    ShaderProgram::NoNormalize)) {
    cout << d->program.error() << endl;
  }
  if (!d->program.enableAttributeArray("color"))
    cout << d->program.error() << endl;
  if (!d->program.useAttributeArray("color", PackedVertex::colorOffset(),
                                    sizeof(PackedVertex), UCharType, 4,
                                    ShaderProgram::Normalize)) {
    cout << d->program.error() << endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!d->program.setUniformValue("modelView", camera.modelView().matrix())) {
    cout << d->program.error() << endl;
  }
  if (!d->program.setUniformValue("projection", camera.projection().matrix())) {
    cout << d->program.error() << endl;
  }

  // Render the linestrips using the shader and bound VBO.
  Array<unsigned int>::const_iterator startIter = m_lineStarts.begin();
  Array<unsigned int>::const_iterator startEnd = m_lineStarts.end();
  Array<float>::const_iterator widthIter = m_lineWidths.begin();
  unsigned int startIndex;
  unsigned int endIndex;
  while (startIter + 1 != startEnd) {
    startIndex = *startIter;
    endIndex = *(startIter + 1);
    glLineWidth(*widthIter);
    glDrawArrays(GL_LINE_STRIP, static_cast<GLint>(startIndex),
                 static_cast<GLsizei>(endIndex - startIndex));
    ++startIter;
    ++widthIter;
  }

  // There is an implicit ending index of m_vertices.size():
  startIndex = *startIter;
  endIndex = static_cast<unsigned int>(m_vertices.size());
  glLineWidth(*widthIter);
  glDrawArrays(GL_LINE_STRIP, static_cast<GLint>(startIndex),
               static_cast<GLsizei>(endIndex - startIndex));

  d->vbo.release();

  d->program.disableAttributeArray("vector");
  d->program.disableAttributeArray("color");

  d->program.release();
}

void LineStripGeometry::clear()
{
  m_vertices.clear();
  m_lineStarts.clear();
  m_lineWidths.clear();
  m_dirty = true;
}

size_t LineStripGeometry::addLineStrip(const Core::Array<Vector3f>& vertices,
                                       const Core::Array<Vector4ub>& rgba,
                                       float lineWidth)
{
  if (vertices.empty() || vertices.size() != rgba.size())
    return InvalidIndex;

  size_t result = m_lineStarts.size();
  m_lineStarts.push_back(static_cast<unsigned int>(m_vertices.size()));
  m_lineWidths.push_back(lineWidth);

  Array<Vector4ub>::const_iterator colorIter(rgba.begin());
  Array<Vector3f>::const_iterator vertIter(vertices.begin());
  Array<Vector3f>::const_iterator vertEnd(vertices.end());

  m_vertices.reserve(m_vertices.size() + vertices.size());
  while (vertIter != vertEnd)
    m_vertices.push_back(PackedVertex(*(vertIter++), *(colorIter++)));

  m_dirty = true;
  return result;
}

size_t LineStripGeometry::addLineStrip(const Core::Array<Vector3f>& vertices,
                                       const Core::Array<Vector3ub>& rgb,
                                       float lineWidth)
{
  if (vertices.empty() || vertices.size() != rgb.size())
    return InvalidIndex;

  size_t result = m_lineStarts.size();
  m_lineStarts.push_back(static_cast<unsigned int>(m_vertices.size()));
  m_lineWidths.push_back(lineWidth);

  Array<Vector3ub>::const_iterator colorIter(rgb.begin());
  Array<Vector3f>::const_iterator vertIter(vertices.begin());
  Array<Vector3f>::const_iterator vertEnd(vertices.end());

  m_vertices.reserve(m_vertices.size() + vertices.size());
  Vector4ub tmpColor(0, 0, 0, m_opacity);
  while (vertIter != vertEnd) {
    tmpColor.head<3>() = *(colorIter++);
    m_vertices.push_back(PackedVertex(*(vertIter++), tmpColor));
  }

  m_dirty = true;
  return result;
}

size_t LineStripGeometry::addLineStrip(const Core::Array<Vector3f>& vertices,
                                       float lineWidth)
{
  if (vertices.empty())
    return InvalidIndex;

  size_t result = m_lineStarts.size();
  m_lineStarts.push_back(static_cast<unsigned int>(m_vertices.size()));
  m_lineWidths.push_back(lineWidth);

  Array<Vector3f>::const_iterator vertIter(vertices.begin());
  Array<Vector3f>::const_iterator vertEnd(vertices.end());

  m_vertices.reserve(m_vertices.size() + vertices.size());
  Vector4ub tmpColor(m_color[0], m_color[1], m_color[2], m_opacity);
  while (vertIter != vertEnd)
    m_vertices.push_back(PackedVertex(*(vertIter++), tmpColor));

  m_dirty = true;
  return result;
}

} // End namespace Rendering
} // End namespace Avogadro

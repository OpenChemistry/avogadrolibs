/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#include "dashedlinegeometry.h"

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
#include "dashedline_vs.h"
}

using Avogadro::Core::Array;
using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

class DashedLineGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;
};

DashedLineGeometry::DashedLineGeometry()
  : m_dirty(false), d(new Private)
{
}

DashedLineGeometry::DashedLineGeometry(const DashedLineGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices), m_colors(other.m_colors),
    m_lineWidths(other.m_lineWidths),
    m_dirty(true),
    d(new Private)
{
}

DashedLineGeometry::~DashedLineGeometry()
{
  delete d;
}

void DashedLineGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void DashedLineGeometry::update()
{
  if (m_vertices.empty())
    return;

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(dashedline_vs);
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

    d->program.detachShader(d->vertexShader);
    d->program.detachShader(d->fragmentShader);
    d->vertexShader.cleanup();
    d->fragmentShader.cleanup();
  }
}

void DashedLineGeometry::render(const Camera& camera)
{
  if (m_vertices.empty() || m_colors.empty() ||
      m_lineWidths.size() != m_colors.size())
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

  // Render the linestrips using the shader and bound VBO.
  Array<Vector3f>::const_iterator startIter = m_vertices.begin();
  Array<Vector3f>::const_iterator startEnd = m_vertices.end();
  Array<Vector4ub>::const_iterator colorIter = m_colors.begin();
  Array<float>::const_iterator widthIter = m_lineWidths.begin();
  unsigned int startIndex;
  unsigned int endIndex;
  while (startIter != startEnd) {
    const Vector3f &start = *startIter;
    const Vector3f &end = *(startIter + 1);
    const Vector4ub &color = *colorIter;
    glColor4ub(color(0), color(1), color(2), color(3));
    glLineWidth(*widthIter);
    glBegin(GL_LINES);
        glVertex3f(start(0), start(1), start(2));
        glVertex3f(end(0), end(1), end(2));
    glEnd();
    startIter += 2;
    ++colorIter;
    ++widthIter;
  }

  d->program.release();
}

void DashedLineGeometry::clear()
{
  m_vertices.clear();
  m_colors.clear();
  m_lineWidths.clear();
  m_dirty = true;
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       const Vector4ub& rgba,
                                       float lineWidth)
{
  size_t result = m_colors.size();
  m_vertices.reserve(m_vertices.size() + 2);
  m_vertices.push_back(start);
  m_vertices.push_back(end);
  m_colors.push_back(rgba);
  m_lineWidths.push_back(lineWidth);

  m_dirty = true;
  return result;
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       const Vector3ub& rgb,
                                       float lineWidth)
{
  Vector4ub rgba = Vector4ub(rgb(0), rgb(1), rgb(2), m_opacity);
  return addDashedLine(start, end, rgba, lineWidth);
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       float lineWidth)
{
  return addDashedLine(start, end, m_color, lineWidth);
}

} // End namespace Rendering
} // End namespace Avogadro

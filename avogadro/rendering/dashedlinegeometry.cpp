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
#include "dashedline_fs.h"
#include "dashedline_vs.h"
}

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

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
  : m_lineWidth(1.0), m_lineCount(0),
    m_color(255, 0, 0), m_opacity(255),
    m_dirty(false), d(new Private)
{
}

DashedLineGeometry::DashedLineGeometry(const DashedLineGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices),
    m_lineWidth(other.m_lineWidth), m_lineCount(other.m_lineCount),
    m_dirty(true), d(new Private)
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

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);
    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(dashedline_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(dashedline_fs);
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
  if (m_vertices.empty())
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

  glEnable(GL_LINE_SMOOTH);
  glLineWidth(m_lineWidth);

  // Render the lines using the shader and bound VBO.
  glDrawArrays(GL_LINES, static_cast<GLint>(0),
               static_cast<GLsizei>(m_vertices.size()));

  glDisable(GL_LINE_SMOOTH);

  d->vbo.release();

  d->program.release();
}

void DashedLineGeometry::clear()
{
  m_vertices.clear();
  m_dirty = true;
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       const Vector4ub &rgba, int dashCount)
{
  const int vertexCount = 2 * dashCount;
  Vector3f delta = (end - start) / (vertexCount - 1);
  Vector3f current = start;
  for (int n = 0; n < vertexCount; n++) {
    m_vertices.push_back(PackedVertex(current, rgba));
    current += delta;
  }

  m_lineCount++;

  m_dirty = true;
  return m_lineCount - 1;
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       const Vector3ub &rgb, int dashCount)
{
  Vector4ub rgba = Vector4ub(rgb(0), rgb(1), rgb(2), m_opacity);
  return addDashedLine(start, end, rgba, dashCount);
}

size_t DashedLineGeometry::addDashedLine(const Vector3f &start, const Vector3f &end,
                                       int dashCount)
{
  return addDashedLine(start, end, m_color, dashCount);
}

} // End namespace Avogadro

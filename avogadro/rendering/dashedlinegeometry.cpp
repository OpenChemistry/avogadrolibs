/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "dashedlinegeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "scene.h"
#include "rendercontext_p.h"
#include "shaderprogram.h"
#include "vertexarrayobject.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

#include <iostream>
#include <limits>

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
  VertexArrayObject vao;
  ContextStamp contextStamp;
};

DashedLineGeometry::DashedLineGeometry()
  : m_lineWidth(1.0), m_lineCount(0), m_color(255, 0, 0), m_opacity(255),
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

  // The program must exist before VAO setup since we need it for attribute
  // setup.
  FallbackRenderContext fallbackContext;
  ShaderProgram* program = RenderContext::currentProgram(ShaderId::DashedLine);
  if (program == nullptr)
    return;

  if (d->contextStamp.forgetIfReplaced(d->vbo, d->vao))
    m_dirty = true;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);

    // Set up VAO with vertex attribute bindings (OpenGL 4.0 core profile)
    d->vao.bind();
    d->vbo.bind();

    if (!program->enableAttributeArray("vertex"))
      cout << program->error() << '\n';
    if (!program->useAttributeArray("vertex", PackedVertex::vertexOffset(),
                                    sizeof(PackedVertex), FloatType, 3,
                                    ShaderProgram::NoNormalize)) {
      cout << program->error() << '\n';
    }
    if (!program->enableAttributeArray("color"))
      cout << program->error() << '\n';
    if (!program->useAttributeArray("color", PackedVertex::colorOffset(),
                                    sizeof(PackedVertex), UCharType, 4,
                                    ShaderProgram::Normalize)) {
      cout << program->error() << '\n';
    }

    d->vao.release();

    m_dirty = false;
  }
}

void DashedLineGeometry::render(const Camera& camera)
{
  if (m_vertices.empty())
    return;

  FallbackRenderContext fallbackContext;

  // Prepare the VBO, VAO, and shader program if necessary.
  update();

  ShaderProgram* program = RenderContext::currentProgram(ShaderId::DashedLine);
  if (program == nullptr)
    return;

  if (!program->bind())
    cout << program->error() << '\n';

  // Bind the VAO (captures all vertex attribute state)
  d->vao.bind();

  RenderContext::useCamera(camera);

#ifndef __EMSCRIPTEN__
  glEnable(GL_LINE_SMOOTH);
#endif
  glLineWidth(m_lineWidth);

  // Render the lines using the shader and VAO.
  glDrawArrays(GL_LINES, static_cast<GLint>(0),
               static_cast<GLsizei>(m_vertices.size()));

#ifndef __EMSCRIPTEN__
  glDisable(GL_LINE_SMOOTH);
#endif

  d->vao.release();
  program->release();
}

void DashedLineGeometry::clear()
{
  m_vertices.clear();
  m_dirty = true;
}

size_t DashedLineGeometry::addDashedLine(const Vector3f& start,
                                         const Vector3f& end,
                                         const Vector4ub& rgba, int dashCount)
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

size_t DashedLineGeometry::addDashedLine(const Vector3f& start,
                                         const Vector3f& end,
                                         const Vector3ub& rgb, int dashCount)
{
  Vector4ub rgba = Vector4ub(rgb(0), rgb(1), rgb(2), m_opacity);
  return addDashedLine(start, end, rgba, dashCount);
}

size_t DashedLineGeometry::addDashedLine(const Vector3f& start,
                                         const Vector3f& end, int dashCount)
{
  return addDashedLine(start, end, m_color, dashCount);
}

} // namespace Avogadro::Rendering

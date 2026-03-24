/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "widelinegeometry.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "shader.h"
#include "shaderprogram.h"
#include "vertexarrayobject.h"
#include "visitor.h"

#include <iostream>

namespace {
#include "wideline_fs.h"
#include "wideline_vs.h"
} // namespace

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;
using Avogadro::Core::Array;

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

class WideLineGeometry::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;
  VertexArrayObject vao;

  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram program;
};

WideLineGeometry::WideLineGeometry()
  : m_color(255, 0, 0), m_opacity(255), m_dirty(false), d(new Private)
{
}

WideLineGeometry::WideLineGeometry(const WideLineGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices), m_indices(other.m_indices),
    m_color(other.m_color), m_opacity(other.m_opacity), m_dirty(true),
    d(new Private)
{
}

WideLineGeometry::~WideLineGeometry()
{
  delete d;
}

void WideLineGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void WideLineGeometry::update()
{
  if (m_vertices.empty())
    return;

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader.type() == Shader::Unknown) {
    d->vertexShader.setType(Shader::Vertex);
    d->vertexShader.setSource(wideline_vs);
    d->fragmentShader.setType(Shader::Fragment);
    d->fragmentShader.setSource(wideline_fs);
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

  // Upload vertex and index data if dirty.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);
    d->ibo.upload(m_indices, BufferObject::ElementArrayBuffer);

    // Set up VAO with vertex attribute bindings
    d->vao.bind();
    d->vbo.bind();
    d->ibo.bind();

    if (!d->program.enableAttributeArray("position"))
      cout << d->program.error() << endl;
    if (!d->program.useAttributeArray(
          "position", PackedVertex::positionOffset(), sizeof(PackedVertex),
          FloatType, 3, ShaderProgram::NoNormalize)) {
      cout << d->program.error() << endl;
    }

    if (!d->program.enableAttributeArray("otherEnd"))
      cout << d->program.error() << endl;
    if (!d->program.useAttributeArray(
          "otherEnd", PackedVertex::otherEndOffset(), sizeof(PackedVertex),
          FloatType, 3, ShaderProgram::NoNormalize)) {
      cout << d->program.error() << endl;
    }

    if (!d->program.enableAttributeArray("color"))
      cout << d->program.error() << endl;
    if (!d->program.useAttributeArray("color", PackedVertex::colorOffset(),
                                      sizeof(PackedVertex), UCharType, 4,
                                      ShaderProgram::Normalize)) {
      cout << d->program.error() << endl;
    }

    if (!d->program.enableAttributeArray("widthSide"))
      cout << d->program.error() << endl;
    if (!d->program.useAttributeArray(
          "widthSide", PackedVertex::widthSideOffset(), sizeof(PackedVertex),
          FloatType, 1, ShaderProgram::NoNormalize)) {
      cout << d->program.error() << endl;
    }

    if (!d->program.enableAttributeArray("lineParam"))
      cout << d->program.error() << endl;
    if (!d->program.useAttributeArray(
          "lineParam", PackedVertex::lineParamOffset(), sizeof(PackedVertex),
          FloatType, 1, ShaderProgram::NoNormalize)) {
      cout << d->program.error() << endl;
    }

    d->vao.release();

    m_dirty = false;
  }
}

void WideLineGeometry::render(const Camera& camera)
{
  if (m_vertices.empty() || m_indices.empty())
    return;

  // Prepare the VBOs, IBO, VAO, and shader program if necessary.
  update();

  if (!d->program.bind())
    cout << d->program.error() << endl;

  // Bind the VAO
  d->vao.bind();

  // Set up our uniforms
  if (!d->program.setUniformValue("modelView", camera.modelView().matrix()))
    cout << d->program.error() << endl;
  if (!d->program.setUniformValue("projection", camera.projection().matrix()))
    cout << d->program.error() << endl;

  // Render the quads
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(m_vertices.size() - 1),
                      static_cast<GLsizei>(m_indices.size()), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vao.release();
  d->program.release();
}

void WideLineGeometry::clear()
{
  m_vertices.clear();
  m_indices.clear();
  m_dirty = true;
}

void WideLineGeometry::reserve(size_t lineCount)
{
  m_vertices.reserve(lineCount * 4);
  m_indices.reserve(lineCount * 6);
}

void WideLineGeometry::addLine(const Vector3f& start, const Vector3f& end,
                               const Vector3ub& colorStart,
                               const Vector3ub& colorEnd, float lineWidth)
{
  float halfWidth = lineWidth * 0.5f;
  auto baseIndex = static_cast<unsigned int>(m_vertices.size());

  Vector4ub rgba1(colorStart[0], colorStart[1], colorStart[2], m_opacity);
  Vector4ub rgba2(colorEnd[0], colorEnd[1], colorEnd[2], m_opacity);

  // Four vertices per line segment: 2 endpoints x 2 sides.
  // End vertices swap position/otherEnd, which reverses the cross product
  // in the vertex shader.  Negate widthSide at the end to compensate,
  // keeping the quad a proper rectangle instead of a bowtie.
  // lineParam = 0 for solid lines (never triggers discard).
  m_vertices.emplace_back(start, end, rgba1, -halfWidth, 0.0f);
  m_vertices.emplace_back(start, end, rgba1, halfWidth, 0.0f);
  m_vertices.emplace_back(end, start, rgba2, halfWidth, 0.0f);
  m_vertices.emplace_back(end, start, rgba2, -halfWidth, 0.0f);

  // Two triangles forming a quad
  m_indices.push_back(baseIndex + 0);
  m_indices.push_back(baseIndex + 1);
  m_indices.push_back(baseIndex + 2);

  m_indices.push_back(baseIndex + 2);
  m_indices.push_back(baseIndex + 1);
  m_indices.push_back(baseIndex + 3);

  m_dirty = true;
}

void WideLineGeometry::addLine(const Vector3f& start, const Vector3f& end,
                               const Vector3ub& color, float lineWidth)
{
  addLine(start, end, color, color, lineWidth);
}

void WideLineGeometry::addLineStrip(const Array<Vector3f>& vertices,
                                    const Vector3ub& color, float lineWidth)
{
  if (vertices.size() < 2)
    return;
  for (size_t i = 0; i + 1 < vertices.size(); ++i)
    addLine(vertices[i], vertices[i + 1], color, lineWidth);
}

void WideLineGeometry::addLineStrip(const Array<Vector3f>& vertices,
                                    const Array<Vector3ub>& colors,
                                    float lineWidth)
{
  if (vertices.size() < 2 || vertices.size() != colors.size())
    return;
  for (size_t i = 0; i + 1 < vertices.size(); ++i)
    addLine(vertices[i], vertices[i + 1], colors[i], colors[i + 1], lineWidth);
}

void WideLineGeometry::addDashedLine(const Vector3f& start, const Vector3f& end,
                                     const Vector3ub& color, float lineWidth,
                                     int dashCount)
{
  if (dashCount <= 0)
    return;

  float halfWidth = lineWidth * 0.5f;
  auto baseIndex = static_cast<unsigned int>(m_vertices.size());

  Vector4ub rgba(color[0], color[1], color[2], m_opacity);

  // lineParam goes from 0 at start to dashCount*2 at end.
  // The fragment shader discards when mod(lineParam, 2.0) > 1.0,
  // producing exactly dashCount dashes with gaps between them.
  float paramEnd = static_cast<float>(dashCount * 2);

  // Use a small epsilon so the very start is not discarded
  m_vertices.emplace_back(start, end, rgba, -halfWidth, 0.01f);
  m_vertices.emplace_back(start, end, rgba, halfWidth, 0.01f);

  // Negate widthSide at the end to compensate for reversed cross product
  m_vertices.emplace_back(end, start, rgba, halfWidth, paramEnd);
  m_vertices.emplace_back(end, start, rgba, -halfWidth, paramEnd);

  m_indices.push_back(baseIndex + 0);
  m_indices.push_back(baseIndex + 1);
  m_indices.push_back(baseIndex + 2);

  m_indices.push_back(baseIndex + 2);
  m_indices.push_back(baseIndex + 1);
  m_indices.push_back(baseIndex + 3);

  m_dirty = true;
}

} // namespace Avogadro::Rendering

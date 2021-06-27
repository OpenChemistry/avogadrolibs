/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "curvegeometry.h"

#include "camera.h"
#include "scene.h"
#include "visitor.h"

namespace {
#include "cylinders_fs.h"
#include "cylinders_vs.h"
} // namespace
#include "avogadrogl.h"

#include <iostream>
#include <vector>

using std::cout;
using std::endl;

namespace Avogadro {
namespace Rendering {

CurveGeometry::CurveGeometry() : m_dirty(true) {}

CurveGeometry::~CurveGeometry()
{
  for (auto& l : m_lines) {
    delete l;
  }
}

void CurveGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void checkShaderInfo(ShaderInfo& shaderInfo, const std::string& fs,
                     const std::string& vs)
{
  if (shaderInfo.vertexShader.type() == Shader::Unknown) {
    shaderInfo.vertexShader.setType(Shader::Vertex);
    shaderInfo.vertexShader.setSource(vs);
    shaderInfo.fragmentShader.setType(Shader::Fragment);
    shaderInfo.fragmentShader.setSource(fs);
    if (!shaderInfo.vertexShader.compile())
      cout << shaderInfo.vertexShader.error() << endl;
    if (!shaderInfo.fragmentShader.compile())
      cout << shaderInfo.fragmentShader.error() << endl;
    shaderInfo.program.attachShader(shaderInfo.vertexShader);
    shaderInfo.program.attachShader(shaderInfo.fragmentShader);
    if (!shaderInfo.program.link())
      cout << shaderInfo.program.error() << endl;
  }
}

void CurveGeometry::processShaderError(bool error)
{
  if (error) {
    cout << m_shaderInfo.program.error() << endl;
  }
}

void CurveGeometry::render(const Camera& camera)
{
  if (m_dirty) {
    checkShaderInfo(m_shaderInfo, cylinders_fs, cylinders_vs);
    m_dirty = false;
  }
  if (!m_dirty) {
    processShaderError(!m_shaderInfo.program.bind());
    processShaderError(!m_shaderInfo.program.setUniformValue(
      "modelView", camera.modelView().matrix()));
    processShaderError(!m_shaderInfo.program.setUniformValue(
      "projection", camera.projection().matrix()));
    Eigen::Matrix3f normalMatrix =
      camera.modelView().linear().inverse().transpose();
    processShaderError(
      !m_shaderInfo.program.setUniformValue("normalMatrix", normalMatrix));

    for (size_t i = 0; i < m_lines.size(); ++i) {
      Line* line = m_lines[i];
      if (line->dirty) {
        update(i);
      }

      line->vbo.bind();
      line->ibo.bind();

      processShaderError(!m_shaderInfo.program.enableAttributeArray("vertex"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "vertex", ColorNormalVertex::vertexOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize));

      processShaderError(!m_shaderInfo.program.enableAttributeArray("color"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "color", ColorNormalVertex::colorOffset(), sizeof(ColorNormalVertex),
        UCharType, 3, ShaderProgram::Normalize));

      processShaderError(!m_shaderInfo.program.enableAttributeArray("normal"));
      processShaderError(!m_shaderInfo.program.useAttributeArray(
        "normal", ColorNormalVertex::normalOffset(), sizeof(ColorNormalVertex),
        FloatType, 3, ShaderProgram::NoNormalize));
      if (line->flat) {
        glLineWidth(-line->radius);
      }
      glDrawRangeElements(line->flat ? GL_LINE_STRIP : GL_TRIANGLES, 0,
                          static_cast<GLuint>(line->numberOfVertices),
                          static_cast<GLsizei>(line->numberOfIndices),
                          GL_UNSIGNED_INT, reinterpret_cast<const GLvoid*>(0));
      line->vbo.release();
      line->ibo.release();
      m_shaderInfo.program.disableAttributeArray("vector");
      m_shaderInfo.program.disableAttributeArray("color");
      m_shaderInfo.program.disableAttributeArray("normal");
    }
    m_shaderInfo.program.release();
  }
}

void CurveGeometry::addPoint(const Vector3f& pos, const Vector3ub& color,
                             float radius, size_t i)
{
  if (m_indexMap.find(i) == m_indexMap.end()) {
    m_indexMap[i] = m_lines.size();
    m_lines.push_back(new Line(radius));
  }
  m_lines[m_indexMap[i]]->radius = radius;
  m_lines[m_indexMap[i]]->flat = radius < 0.0f;
  m_lines[m_indexMap[i]]->add(new Point(pos, color));
}

} // namespace Rendering
} // namespace Avogadro

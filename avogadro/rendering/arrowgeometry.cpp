/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
#include <cmath>

namespace {
#include "arrow_vs.h"
#include "arrow_fs.h"
} // namespace

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

using std::cout;
using std::endl;

namespace Avogadro::Rendering {

class ArrowGeometry::Private
{
public:
  Private() {}

  inline static Shader* cylinderVertexShader = nullptr;
  inline static Shader* cylinderFragmentShader = nullptr;
  inline static ShaderProgram* cylinderProgram = nullptr;

  inline static Shader* coneVertexShader = nullptr;
  inline static Shader* coneFragmentShader = nullptr;
  inline static ShaderProgram* coneProgram = nullptr;
};

ArrowGeometry::ArrowGeometry()
  : m_color(0, 255, 0), m_dirty(false), m_geometryDirty(true), m_cylinderVAO(0),
    m_cylinderVBO(0), m_cylinderEBO(0), m_coneVAO(0), m_coneVBO(0),
    m_coneEBO(0), m_cylinderIndexCount(0), m_coneIndexCount(0),
    m_cylinderRadius(0.02f), m_coneRadius(0.05f), m_coneFraction(0.2f),
    d(new Private)
{
}

ArrowGeometry::ArrowGeometry(const ArrowGeometry& other)
  : Drawable(other), m_vertices(other.m_vertices),
    m_lineStarts(other.m_lineStarts), m_color(other.m_color), m_dirty(true),
    m_geometryDirty(true), m_cylinderVAO(0), m_cylinderVBO(0), m_cylinderEBO(0),
    m_coneVAO(0), m_coneVBO(0), m_coneEBO(0), m_cylinderIndexCount(0),
    m_coneIndexCount(0), m_cylinderRadius(other.m_cylinderRadius),
    m_coneRadius(other.m_coneRadius), m_coneFraction(other.m_coneFraction),
    d(new Private)
{
}

ArrowGeometry::~ArrowGeometry()
{
  if (m_cylinderVAO)
    glDeleteVertexArrays(1, &m_cylinderVAO);
  if (m_cylinderVBO)
    glDeleteBuffers(1, &m_cylinderVBO);
  if (m_cylinderEBO)
    glDeleteBuffers(1, &m_cylinderEBO);
  if (m_coneVAO)
    glDeleteVertexArrays(1, &m_coneVAO);
  if (m_coneVBO)
    glDeleteBuffers(1, &m_coneVBO);
  if (m_coneEBO)
    glDeleteBuffers(1, &m_coneEBO);
  delete d;
}

void ArrowGeometry::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void ArrowGeometry::generateCylinderGeometry(std::vector<float>& vertices,
                                             std::vector<unsigned int>& indices,
                                             int segments)
{
  vertices.clear();
  indices.clear();

  // Generate vertices (position + normal)
  for (int i = 0; i <= segments; ++i) {
    float theta = 2.0f * M_PI * i / segments;
    float x = m_cylinderRadius * cos(theta);
    float z = m_cylinderRadius * sin(theta);

    // Bottom circle
    vertices.push_back(x);
    vertices.push_back(0.0f);
    vertices.push_back(z);
    vertices.push_back(x / m_cylinderRadius); // Normal
    vertices.push_back(0.0f);
    vertices.push_back(z / m_cylinderRadius);

    // Top circle
    vertices.push_back(x);
    vertices.push_back(1.0f);
    vertices.push_back(z);
    vertices.push_back(x / m_cylinderRadius); // Normal
    vertices.push_back(0.0f);
    vertices.push_back(z / m_cylinderRadius);
  }

  // Generate indices
  for (int i = 0; i < segments; ++i) {
    int bottom1 = i * 2;
    int top1 = i * 2 + 1;
    int bottom2 = (i + 1) * 2;
    int top2 = (i + 1) * 2 + 1;

    indices.push_back(bottom1);
    indices.push_back(top1);
    indices.push_back(bottom2);

    indices.push_back(bottom2);
    indices.push_back(top1);
    indices.push_back(top2);
  }
}

void ArrowGeometry::generateConeGeometry(std::vector<float>& vertices,
                                         std::vector<unsigned int>& indices,
                                         int segments)
{
  vertices.clear();
  indices.clear();

  // Apex
  vertices.push_back(0.0f);
  vertices.push_back(1.0f);
  vertices.push_back(0.0f);
  vertices.push_back(0.0f);
  vertices.push_back(1.0f);
  vertices.push_back(0.0f);

  // Base circle
  for (int i = 0; i <= segments; ++i) {
    float theta = 2.0f * M_PI * i / segments;
    float x = m_coneRadius * cos(theta);
    float z = m_coneRadius * sin(theta);

    vertices.push_back(x);
    vertices.push_back(0.0f);
    vertices.push_back(z);

    // Normal (approximate for cone)
    Vector3f toApex(-x, 1.0f, -z);
    toApex.normalize();
    Vector3f tangent(-sin(theta), 0.0f, cos(theta));
    Vector3f normal = toApex.cross(tangent);
    normal.normalize();

    vertices.push_back(normal.x());
    vertices.push_back(normal.y());
    vertices.push_back(normal.z());
  }

  // Generate indices
  for (int i = 1; i <= segments; ++i) {
    indices.push_back(0);
    indices.push_back(i);
    indices.push_back(i + 1);
  }
}

void ArrowGeometry::updateGeometry()
{
  if (!m_geometryDirty)
    return;

  std::vector<float> vertices;
  std::vector<unsigned int> indices;

  // Setup cylinder
  generateCylinderGeometry(vertices, indices);
  m_cylinderIndexCount = indices.size();

  if (!m_cylinderVAO)
    glGenVertexArrays(1, &m_cylinderVAO);
  if (!m_cylinderVBO)
    glGenBuffers(1, &m_cylinderVBO);
  if (!m_cylinderEBO)
    glGenBuffers(1, &m_cylinderEBO);

  glBindVertexArray(m_cylinderVAO);

  glBindBuffer(GL_ARRAY_BUFFER, m_cylinderVBO);
  glBufferData(GL_ARRAY_BUFFER, vertices.size() * sizeof(float),
               vertices.data(), GL_STATIC_DRAW);

  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, m_cylinderEBO);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, indices.size() * sizeof(unsigned int),
               indices.data(), GL_STATIC_DRAW);

  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float), (void*)0);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float),
                        (void*)(3 * sizeof(float)));
  glEnableVertexAttribArray(1);

  // Setup cone
  generateConeGeometry(vertices, indices);
  m_coneIndexCount = indices.size();

  if (!m_coneVAO)
    glGenVertexArrays(1, &m_coneVAO);
  if (!m_coneVBO)
    glGenBuffers(1, &m_coneVBO);
  if (!m_coneEBO)
    glGenBuffers(1, &m_coneEBO);

  glBindVertexArray(m_coneVAO);

  glBindBuffer(GL_ARRAY_BUFFER, m_coneVBO);
  glBufferData(GL_ARRAY_BUFFER, vertices.size() * sizeof(float),
               vertices.data(), GL_STATIC_DRAW);

  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, m_coneEBO);
  glBufferData(GL_ELEMENT_ARRAY_BUFFER, indices.size() * sizeof(unsigned int),
               indices.data(), GL_STATIC_DRAW);

  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float), (void*)0);
  glEnableVertexAttribArray(0);
  glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 6 * sizeof(float),
                        (void*)(3 * sizeof(float)));
  glEnableVertexAttribArray(1);

  glBindVertexArray(0);
  m_geometryDirty = false;
}

void ArrowGeometry::update()
{
  if (m_vertices.empty())
    return;

  // Build shaders if not already done
  if (d->cylinderProgram == nullptr) {
    d->cylinderProgram = new ShaderProgram;
    d->cylinderVertexShader = new Shader;
    d->cylinderVertexShader->setType(Shader::Vertex);
    d->cylinderVertexShader->setSource(arrow_vs);
    if (!d->cylinderVertexShader->compile())
      cout << "Cylinder vertex shader: " << d->cylinderVertexShader->error()
           << endl;

    d->cylinderFragmentShader = new Shader;
    d->cylinderFragmentShader->setType(Shader::Fragment);
    d->cylinderFragmentShader->setSource(arrow_fs);
    if (!d->cylinderFragmentShader->compile())
      cout << "Cylinder fragment shader: " << d->cylinderFragmentShader->error()
           << endl;

    d->cylinderProgram->attachShader(*d->cylinderVertexShader);
    d->cylinderProgram->attachShader(*d->cylinderFragmentShader);
    if (!d->cylinderProgram->link())
      cout << "Cylinder program: " << d->cylinderProgram->error() << endl;
  }

  if (d->coneProgram == nullptr) {
    d->coneProgram = new ShaderProgram;
    d->coneVertexShader = new Shader;
    d->coneVertexShader->setType(Shader::Vertex);
    d->coneVertexShader->setSource(arrow_vs);
    if (!d->coneVertexShader->compile())
      cout << "Cone vertex shader: " << d->coneVertexShader->error() << endl;

    d->coneFragmentShader = new Shader;
    d->coneFragmentShader->setType(Shader::Fragment);
    d->coneFragmentShader->setSource(arrow_fs);
    if (!d->coneFragmentShader->compile())
      cout << "Cone fragment shader: " << d->coneFragmentShader->error()
           << endl;

    d->coneProgram->attachShader(*d->coneVertexShader);
    d->coneProgram->attachShader(*d->coneFragmentShader);
    if (!d->coneProgram->link())
      cout << "Cone program: " << d->coneProgram->error() << endl;
  }

  updateGeometry();
}

void ArrowGeometry::render(const Camera& camera)
{
  if (m_vertices.empty())
    return;

  // Prepare the shader program if necessary.
  update();

  Vector3f floatColor(m_color[0] / 255.0f, m_color[1] / 255.0f,
                      m_color[2] / 255.0f);

  // Render each arrow
  for (const auto& arrow : m_vertices) {
    Vector3f direction = arrow.second - arrow.first;
    float length = direction.norm();

    if (length < 0.001f)
      continue;

    direction.normalize();
    float coneLength = length * m_coneFraction;
    float cylinderLength = length - coneLength;

    // Calculate rotation to align with direction
    Vector3f up(0.0f, 1.0f, 0.0f);
    Vector3f axis = up.cross(direction);
    float axisLength = axis.norm();

    Eigen::Matrix4f rotation = Eigen::Matrix4f::Identity();
    if (axisLength > 0.001f) {
      axis.normalize();
      float angle = acos(up.dot(direction));

      // Rodrigues' rotation formula
      float c = cos(angle);
      float s = sin(angle);
      float t = 1.0f - c;

      rotation(0, 0) = t * axis.x() * axis.x() + c;
      rotation(0, 1) = t * axis.x() * axis.y() - s * axis.z();
      rotation(0, 2) = t * axis.x() * axis.z() + s * axis.y();
      rotation(1, 0) = t * axis.x() * axis.y() + s * axis.z();
      rotation(1, 1) = t * axis.y() * axis.y() + c;
      rotation(1, 2) = t * axis.y() * axis.z() - s * axis.x();
      rotation(2, 0) = t * axis.x() * axis.z() - s * axis.y();
      rotation(2, 1) = t * axis.y() * axis.z() + s * axis.x();
      rotation(2, 2) = t * axis.z() * axis.z() + c;
    } else if (direction.y() < 0) {
      rotation(1, 1) = -1.0f;
      rotation(2, 2) = -1.0f;
    }

    // Render cylinder
    if (d->cylinderProgram->bind()) {
      Eigen::Matrix4f model = Eigen::Matrix4f::Identity();
      model.block<3, 1>(0, 3) = arrow.first;
      model.block<3, 3>(0, 0) = rotation.block<3, 3>(0, 0);

      // Scale
      Eigen::Matrix4f scale = Eigen::Matrix4f::Identity();
      scale(1, 1) = cylinderLength;
      model = model * scale;

      d->cylinderProgram->setUniformValue("modelView",
                                          camera.modelView().matrix());
      d->cylinderProgram->setUniformValue("projection",
                                          camera.projection().matrix());
      d->cylinderProgram->setUniformValue("model", model);
      d->cylinderProgram->setUniformValue("color", floatColor);

      glBindVertexArray(m_cylinderVAO);
      glDrawElements(GL_TRIANGLES, m_cylinderIndexCount, GL_UNSIGNED_INT, 0);

      d->cylinderProgram->release();
    }

    // Render cone
    if (d->coneProgram->bind()) {
      Vector3f coneBase = arrow.first + direction * cylinderLength;

      Eigen::Matrix4f model = Eigen::Matrix4f::Identity();
      model.block<3, 1>(0, 3) = coneBase;
      model.block<3, 3>(0, 0) = rotation.block<3, 3>(0, 0);

      // Scale
      Eigen::Matrix4f scale = Eigen::Matrix4f::Identity();
      scale(1, 1) = coneLength;
      model = model * scale;

      d->coneProgram->setUniformValue("modelView", camera.modelView().matrix());
      d->coneProgram->setUniformValue("projection",
                                      camera.projection().matrix());
      d->coneProgram->setUniformValue("model", model);
      d->coneProgram->setUniformValue("color", floatColor);

      glBindVertexArray(m_coneVAO);
      glDrawElements(GL_TRIANGLES, m_coneIndexCount, GL_UNSIGNED_INT, 0);

      d->coneProgram->release();
    }
  }

  glBindVertexArray(0);
}

void ArrowGeometry::clear()
{
  m_vertices.clear();
  m_lineStarts.clear();
  m_dirty = true;
}

void ArrowGeometry::addSingleArrow(const Vector3f& pos1, const Vector3f& pos2)
{
  m_vertices.reserve(m_vertices.size() + 1);
  m_vertices.push_back(std::pair<Vector3f, Vector3f>(pos1, pos2));
  m_dirty = true;
}

} // namespace Avogadro::Rendering

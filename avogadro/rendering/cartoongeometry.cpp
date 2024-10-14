/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "cartoongeometry.h"
#include "shader.h"
#include "shaderprogram.h"
#include "camera.h"
#include "bufferobject.h"



#include <cmath>

namespace {

#include "bspline_vs.h"
#include "bspline_fs.h"
#include "bspline_tcs.h"
#include "bspline_tev.h"

} // namespace

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Vector4ub;

namespace Avogadro::Rendering {

class Cartoon::Private
{
public:
  Private() {}

  BufferObject vbo;
  BufferObject ibo;

  inline static Shader* vertexShader = nullptr;
  inline static Shader* fragmentShader = nullptr;
  inline static Shader* fragmentShaderOpaque = nullptr;
  inline static ShaderProgram* program = nullptr;
  inline static ShaderProgram* programOpaque = nullptr;

  size_t numberOfVertices;
  size_t numberOfIndices;
};


using Core::Residue;
using std::vector;

const float Cartoon::ELIPSE_RATIO = 0.75f;

Cartoon::Cartoon()
  : BSplineGeometry(false), m_minRadius(-1.0f), m_maxRadius(-1.0f), m_dirty(false), d(new Private)
{}

Cartoon::Cartoon(float minRadius, float maxRadius)
  : BSplineGeometry(false), m_minRadius(minRadius), m_maxRadius(maxRadius), m_dirty(true),
    d(new Private),  m_vertices(other.m_vertices), m_indices(other.m_indices)
{}

Cartoon::~Cartoon()
{
  delete d;
}

void Cartoon::update()
{
  if (m_vertices.empty() || m_indices.empty())
    return;

  // Check if the VBOs are ready, if not get them ready.
  if (!d->vbo.ready() || m_dirty) {
    d->vbo.upload(m_vertices, BufferObject::ArrayBuffer);
    d->ibo.upload(m_indices, BufferObject::ElementArrayBuffer);
    d->numberOfVertices = m_vertices.size();
    d->numberOfIndices = m_indices.size();
    m_dirty = false;
  }

  // Build and link the shader if it has not been used yet.
  if (d->vertexShader == nullptr) {
    d->vertexShader = new Shader;
    d->vertexShader->setType(Shader::Vertex);
    d->vertexShader->setSource(bspline_vs);

    d->fragmentShader = new Shader;
    d->fragmentShader->setType(Shader::Fragment);
    d->fragmentShader->setSource(bspline_fs);

    if (!d->vertexShader->compile())
      std::cout << d->vertexShader->error() << std::endl;
    if (!d->fragmentShader->compile())
      std::cout << d->fragmentShader->error() << std::endl;

    if (d->program == nullptr)
      d->program = new ShaderProgram;
    d->program->attachShader(*d->vertexShader);
    d->program->attachShader(*d->fragmentShader);
    if (!d->program->link())
      std::cout << d->program->error() << std::endl;
  }
}

void Cartoon::render(const Camera& camera)
{
  if (m_indices.empty() || m_vertices.empty())
    return;

  // Prepare the VBOs, IBOs and shader program if necessary.
  update();

  ShaderProgram* program;
  program = d->programOpaque;

  if (!program->bind())
    std::cout << program->error() << std::endl;

  d->vbo.bind();
  d->ibo.bind();

  // Set up our attribute arrays.
  if (!program->enableAttributeArray("vertex"))
    std::cout << program->error() << std::endl;
  if (!program->useAttributeArray("vertex", PackedVertex::vertexOffset(),
                                 sizeof(PackedVertex), FloatType, 3,
                                 ShaderProgram::NoNormalize)) {
    std::cout << program->error() << std::endl;
  }
  if (!program->enableAttributeArray("color"))
    std::cout << program->error() << std::endl;
  if (!program->useAttributeArray("color", PackedVertex::colorOffset(),
                                 sizeof(PackedVertex), UCharType, 4,
                                 ShaderProgram::Normalize)) {
    std::cout << program->error() << std::endl;
  }
  if (!program->enableAttributeArray("normal"))
    std::cout << program->error() << std::endl;
  if (!program->useAttributeArray("normal", PackedVertex::normalOffset(),
                                 sizeof(PackedVertex), FloatType, 3,
                                 ShaderProgram::NoNormalize)) {
    std::cout << program->error() << std::endl;
  }

  // Set up our uniforms (model-view and projection matrices right now).
  if (!program->setUniformValue("modelView", camera.modelView().matrix())) {
    std::cout << program->error() << std::endl;
  }
  if (!program->setUniformValue("projection", camera.projection().matrix())) {
    std::cout << program->error() << std::endl;
  }
  Matrix3f normalMatrix = camera.modelView().linear().inverse().transpose();
  if (!program->setUniformValue("normalMatrix", normalMatrix))
    std::cout << program->error() << std::endl;

  // Render the loaded spheres using the shader and bound VBO.
  glDrawRangeElements(GL_TRIANGLES, 0,
                      static_cast<GLuint>(d->numberOfVertices - 1),
                      static_cast<GLsizei>(d->numberOfIndices), GL_UNSIGNED_INT,
                      reinterpret_cast<const GLvoid*>(0));

  d->vbo.release();
  d->ibo.release();

  program->disableAttributeArray("vertex");
  program->disableAttributeArray("color");
  program->disableAttributeArray("normal");

  program->release();
}


vector<ColorNormalVertex> Cartoon::computeCirclePoints(const Eigen::Affine3f& a,
                                                       const Eigen::Affine3f& b,
                                                       bool flat) const
{
  unsigned int circleResolution = flat ? 2 : 20;
  const float resolutionRadians =
    2.0f * static_cast<float>(M_PI) / static_cast<float>(circleResolution);
  vector<ColorNormalVertex> result;
  float elipseA = flat ? 0.999f : ELIPSE_RATIO;
  float elipseB = 1.0f - elipseA;
  float e = std::sqrt(1.0f - ((elipseB * elipseB) / (elipseA * elipseA)));
  float c = elipseA * e;
  for (unsigned int i = 0; i < circleResolution; ++i) {
    float theta = resolutionRadians * i;
    float r = (elipseA * (1.0f - (e * e))) / (1.0f + e * std::cos(theta));
    Vector3f elipse =
      Vector3f(r * std::sin(theta), 0.0f, c + r * std::cos(theta));

    ColorNormalVertex vert1;
    vert1.normal = a.linear() * elipse;
    vert1.vertex = a * elipse;
    result.push_back(vert1);

    ColorNormalVertex vert2;
    vert2.normal = b.linear() * elipse;
    vert2.vertex = b * elipse;
    result.push_back(vert2);
  }
  return result;
}

float arrowFunction(float t)
{
  float result;
  const float maxPoint = 0.7f;
  if (t < maxPoint) {
    // normalize t using max point and scale it so that adding will be between
    // [minimumRadius, 1]
    result = t / maxPoint;
  } else {
    // starting with 1 and go decreassing
    t = (t - maxPoint) / (1.0f - maxPoint);
    result = 1.0f - t;
    result = result < 0.3 ? 0.3 : result;
  }
  return result;
}

float Cartoon::computeScale(size_t index, float p, float radius) const
{
  if (index > m_type.size())
    return radius;
  float t = (m_type[index].second + p) / 0.80f;
  t = t > 1.0f ? 1.0f : t;
  switch (m_type[index].first) {
    default:
    case Undefined:
      return radius;
    case Body:
      return m_minRadius;
    case Arrow:
      if (m_type[index].second == 0) {
        return (arrowFunction(1.0f - t) * m_maxRadius) + m_minRadius;
      } else {
        return 0.3 * m_maxRadius + m_minRadius;
      }
    case Head:
      return ((1.0f - t) * (m_maxRadius - m_minRadius)) + (1.0f * m_minRadius);
    case Tail:
      return (t * (m_maxRadius - m_minRadius)) + (1.0f * m_minRadius);
  }
}

CartoonType secondaryToCartoonType(Residue::SecondaryStructure sec)
{
  switch (sec) {
    case Residue::SecondaryStructure::betaSheet:
      return Arrow;
    case Residue::SecondaryStructure::alphaHelix:
      return Tail;
    default:
      return Body;
  }
}

void Cartoon::addPoint(const Vector3f& pos, const Vector3ub& color,
                       size_t group, size_t id, Residue::SecondaryStructure sec)
{
  CartoonType ct = secondaryToCartoonType(sec);
  size_t idCartoon = 0;
  if (m_type.size() > 0) {
    idCartoon = ct == m_type.back().first && m_type.size() > (SKIPPED + 1)
                  ? m_type.back().second + 1
                  : 0;
    if (Tail == m_type.back().first && ct == Body) {
      for (size_t i = m_type.size(), j = 0;
           i > 0 && j < std::ceil(m_type.back().second / 2.0f); --i, ++j) {
        m_type[i - 1].first = Head;
        m_type[i - 1].second = j;
      }
    }
    if (ct == Arrow && m_type.back().first == Arrow) {
      m_type.back().second = 1;
      idCartoon = 0;
    }
  }
  m_type.emplace_back(ct, idCartoon);
  BSplineGeometry::addPoint(pos, color, m_minRadius, group, id);
}

} // namespace Avogadro

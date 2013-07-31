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

#include "texture2d.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "quadplacementstrategy.h"
#include "scene.h"
#include "shader.h"
#include "shaderprogram.h"
#include "visitor.h"

#include <avogadro/core/matrix.h>

#include <iostream>

// Bring in our shader sources:
namespace {
#include "texture2d_fs.h"
#include "texture2d_vs.h"
} // end anon namespace

using Avogadro::Core::Array;

namespace Avogadro {
namespace Rendering {

class Texture2D::Private
{
public:
  Private() : textureIdSet(false) { }
  ~Private()
  {
    if (textureIdSet)
      glDeleteTextures(1, &textureId);
  }

  BufferObject vertexBuffer;
  BufferObject tcoordBuffer;

  Shader vShader;
  Shader fShader;
  ShaderProgram program;

  bool textureIdSet;
  GLuint textureId;

  std::vector<Vector3f> quad;
  std::vector<Vector2f> tcoords;
};

Texture2D::Texture2D()
  : Drawable(),
    m_quadPlacementStrategy(NULL),
    m_textureSynced(false),
    d(new Private)
{
  m_textureSize[0] = 0;
  m_textureSize[1] = 0;
}

Texture2D::~Texture2D()
{
  delete d;
}

void Texture2D::accept(Visitor &v)
{
  v.visit(*this);
}

void Texture2D::render(const Camera &camera)
{
  if (m_textureData.empty())
    return;

  // Upload geometry and textures, build and link shaders:
  if (!prepareGl(camera))
    return;

  Matrix4f mvp(camera.projection().matrix() * camera.modelView().matrix());

  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, d->textureId);

  if (!d->program.bind()
      || !d->program.setUniformValue("mvp", mvp)
      || !d->program.setUniformValue("texture", 0)
      || !d->program.enableAttributeArray("vertex")
      || !d->program.enableAttributeArray("texCoord")
      || !d->vertexBuffer.bind()
      || !d->program.useAttributeArray("vertex", 0, 0, ShaderProgram::FloatT, 3)
      || !d->vertexBuffer.release()
      || !d->tcoordBuffer.bind()
      || !d->program.useAttributeArray("texCoord", 0, 0, ShaderProgram::FloatT,
                                       2)
      || !d->tcoordBuffer.release()
      ) {
    std::cerr << d->program.error() << std::endl;
  }

  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

  glBindTexture(GL_TEXTURE_2D, 0);
  d->program.disableAttributeArray("vertex");
  d->program.disableAttributeArray("texCoord");
  d->program.release();
}

void Texture2D::setTextureData(const Core::Array<unsigned char> &data,
                               size_t width, size_t height)
{
  m_textureData = data;
  m_textureSize[0] = width;
  m_textureSize[1] = height;
  m_textureSynced = false;
}

Core::Array<unsigned char> Texture2D::textureData() const
{
  return m_textureData;
}

void Texture2D::textureSize(size_t size[2]) const
{
  size[0] = m_textureSize[0];
  size[1] = m_textureSize[1];
}

void Texture2D::setQuadPlacementStrategy(QuadPlacementStrategy *strategy)
{
  if (m_quadPlacementStrategy != strategy) {
    delete m_quadPlacementStrategy;
    m_quadPlacementStrategy = strategy;
  }
}

const QuadPlacementStrategy *Texture2D::quadPlacementStrategy() const
{
  return m_quadPlacementStrategy;
}

QuadPlacementStrategy *Texture2D::quadPlacementStrategy()
{
  return m_quadPlacementStrategy;
}

void Texture2D::setTextureCoordinates(const Core::Array<Vector2f> tcoords)
{
  m_textureCoordinates = tcoords;
}

Core::Array<Vector2f> Texture2D::textureCoordinates() const
{
  return m_textureCoordinates;
}

bool Texture2D::prepareGl(const Camera &camera)
{
  // Fetch the quad from the current strategy
  if (!m_quadPlacementStrategy) {
    std::cerr << "Avogadro::Rendering::Texture2D::prepareGL error: "
                 "no quad placement strategy set!" << std::endl;
    return false;
  }

  Array<Vector3f> quad(m_quadPlacementStrategy->quad(camera));
  if (quad.size() != 4) {
    std::cerr << "Avogadro::Rendering::Texture2D::prepareGL error: "
                 "invalid quad size: " << quad.size() << std::endl;
    return false;
  }

  // Upload the quad if it changed
  if (d->quad.size() != 4
      || !std::equal(quad.begin(), quad.end(), d->quad.begin())) {
    d->quad.resize(4);
    std::copy(quad.begin(), quad.end(), d->quad.begin());
    if (!d->vertexBuffer.upload(d->quad, BufferObject::ARRAY_BUFFER)) {
      std::cerr << d->vertexBuffer.error() << std::endl;
      return false;
    }
  }

  // Upload tcoords if they've changed
  if (m_textureCoordinates.size() != 4) {
    std::cerr << "Avogadro::Rendering::Texture2D::prepareGL error: "
                 "invalid texture coordinate array length: "
              << m_textureCoordinates.size() << std::endl;
    return false;
  }

  if (d->tcoords.size() != 4
      || !std::equal(d->tcoords.begin(), d->tcoords.end(),
                     m_textureCoordinates.begin())) {
    d->tcoords.resize(4);
    std::copy(m_textureCoordinates.begin(), m_textureCoordinates.end(),
              d->tcoords.begin());
    if (!d->tcoordBuffer.upload(d->tcoords, BufferObject::ARRAY_BUFFER)) {
      std::cerr << d->tcoordBuffer.error() << std::endl;
      return false;
    }
  }

  if (!m_textureSynced) {
    if (!d->textureIdSet) {
      glGenTextures(1, &d->textureId);
      d->textureIdSet = true;
    }

    /// @todo We'll want to generalize this eventually...
    glBindTexture(GL_TEXTURE_2D, d->textureId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexImage2D(
          GL_TEXTURE_2D, 0, GL_RGBA, static_cast<GLsizei>(m_textureSize[0]),
          static_cast<GLsizei>(m_textureSize[1]), 0, GL_RGBA, GL_UNSIGNED_BYTE,
          m_textureData.data());
    m_textureSynced = true;
  }

  // Compile and link shaders if needed
  if (d->vShader.type() == Shader::Unknown) {
    d->vShader.setType(Shader::Vertex);
    d->vShader.setSource(texture2d_vs);
    d->fShader.setType(Shader::Fragment);
    d->fShader.setSource(texture2d_fs);
    if (!d->vShader.compile())
      std::cerr << d->vShader.error() << std::endl;
    if (!d->fShader.compile())
      std::cerr << d->fShader.error() << std::endl;
    d->program.attachShader(d->vShader);
    d->program.attachShader(d->fShader);
    if (!d->program.link())
      std::cerr << d->program.error() << std::endl;
  }

  return true;
}

} // namespace Rendering
} // namespace Avogadro

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

namespace Avogadro {
namespace Rendering {

class Texture2D::Private
{
public:
  Private() : textureIdSet(false) { }

  BufferObject vertexBuffer;
  BufferObject tcoordBuffer;

  Shader vShader;
  Shader fShader;
  ShaderProgram program;

  bool textureIdSet;
  GLuint textureId;
};

Texture2D::Texture2D()
  : Drawable(),
    m_geometrySynced(false),
    m_textureSynced(false),
    m_textureData(),
    m_quad(4, Vector3f(0.f, 0.f, 0.f)),
    m_textureCoordinates(4, Vector2f(0.f, 0.f)),
    d(new Private)
{
  m_textureSize[0] = 0;
  m_textureSize[1] = 0;
}

Texture2D::~Texture2D()
{
  if (d->textureIdSet)
    glDeleteTextures(1, &d->textureId);
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
  prepareGl();

  Matrix4f mvp(camera.projection().matrix() * camera.modelView().matrix());

  glActiveTexture(GL_TEXTURE0);
  glBindTexture(GL_TEXTURE_2D, d->textureId);

  if (!d->program.bind()
      || !d->program.setUniformValue("mvp", mvp)
      || !d->program.setUniformValue("texture", 0)
      || !d->program.enableAttributeArray("vertex")
      || !d->program.enableAttributeArray("texCoord")
      || !d->vertexBuffer.bind()
      || !d->program.useAttributeArray("vertex", 0, Vector3f())
      || !d->vertexBuffer.release()
      || !d->tcoordBuffer.bind()
      || !d->program.useAttributeArray("texCoord", 0, Vector2f())
      || !d->tcoordBuffer.release()
      ) {
    std::cout << d->program.error() << std::endl;
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

void Texture2D::setQuad(const Vector3f quadList[4])
{
  if (!std::equal(quadList, quadList + 4, m_quad.begin())) {
    std::copy(quadList, quadList + 4, m_quad.begin());
    m_geometrySynced = false;
  }
}

void Texture2D::quad(Vector3f quadList[4]) const
{
  std::copy(m_quad.begin(), m_quad.end(), quadList);
}

void Texture2D::setTextureCoordinates(const Vector2f tcoords[4])
{
  if (!std::equal(tcoords, tcoords + 4, m_textureCoordinates.begin())) {
    std::copy(tcoords, tcoords + 4, m_textureCoordinates.begin());
    m_geometrySynced = false;
  }
}

void Texture2D::textureCoordinates(Vector2f tcoords[4]) const
{
  std::copy(m_textureCoordinates.begin(), m_textureCoordinates.end(), tcoords);
}

void Texture2D::prepareGl()
{
  // Upload geometry and tcoords
  if (!m_geometrySynced) {
    std::cout << "Syncing geometry..." << std::endl;
    if (!d->vertexBuffer.upload(m_quad))
      std::cout << d->vertexBuffer.error() << std::endl;
    if (!d->tcoordBuffer.upload(m_textureCoordinates))
      std::cout << d->tcoordBuffer.error() << std::endl;
    m_geometrySynced = true;
  }

  if (!m_textureSynced) {
    std::cout << "Syncing texture...";
    if (!d->textureIdSet) {
      glGenTextures(1, &d->textureId);
      d->textureIdSet = true;
    }
    std::cout << "id=" << d->textureId << std::endl;

    /// @todo We'll want to generalize this eventually. For now,
    /// hardcode for text textures.
    glBindTexture(GL_TEXTURE_2D, d->textureId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, m_textureSize[0], m_textureSize[1],
        0, GL_RGBA, GL_UNSIGNED_BYTE, m_textureData.data());
    m_textureSynced = true;
  }

  // Compile and link shaders if needed
  if (d->vShader.type() == Shader::Unknown) {
    std::cout << "Building shaders..." << std::endl;
      d->vShader.setType(Shader::Vertex);
      d->vShader.setSource(texture2d_vs);
      d->fShader.setType(Shader::Fragment);
      d->fShader.setSource(texture2d_fs);
      if (!d->vShader.compile())
        std::cout << d->vShader.error() << std::endl;
      if (!d->fShader.compile())
        std::cout << d->fShader.error() << std::endl;
      d->program.attachShader(d->vShader);
      d->program.attachShader(d->fShader);
      if (!d->program.link())
        std::cout << d->program.error() << std::endl;
    }
}

} // namespace Rendering
} // namespace Avogadro

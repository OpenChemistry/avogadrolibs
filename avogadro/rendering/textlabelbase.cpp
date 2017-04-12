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

#include "textlabelbase.h"

#include "avogadrogl.h"
#include "bufferobject.h"
#include "camera.h"
#include "shader.h"
#include "shaderprogram.h"
#include "textrenderstrategy.h"
#include "texture2d.h"
#include "visitor.h"

#include <avogadro/core/array.h>
#include <avogadro/core/matrix.h>
#include <avogadro/core/vector.h>

namespace {
#include "textlabelbase_fs.h"
#include "textlabelbase_vs.h"
} // end anon namespace

#include <iostream>

using Avogadro::Core::Array;

namespace Avogadro {
namespace Rendering {

class TextLabelBase::RenderImpl
{
public:
  struct PackedVertex
  {
    Vector2i offset; //  8 bytes (8)
    Vector2f tcoord; //  8 bytes (16)

    PackedVertex() : offset(0, 0), tcoord(0.f, 0.f) {}

    static int offsetOffset() { return 0; }
    static int tcoordOffset() { return static_cast<int>(sizeof(Vector2i)); }
  };

  // Actual vertex data
  Array<PackedVertex> vertices;
  BufferObject vbo;

  // Sentinals:
  bool shadersInvalid;
  bool textureInvalid;
  bool vboInvalid;

  // Uniforms:
  Vector3f anchor;
  float radius;
  Texture2D texture;

  // Shaders
  Shader vertexShader;
  Shader fragmentShader;
  ShaderProgram shaderProgram;

  RenderImpl();
  ~RenderImpl() {}

  void setTextureData(const Array<unsigned char>& buffer,
                      const Vector2i& dimensions);

  void setOffsets(const Vector2i& dimensions, TextProperties::HAlign hAlign,
                  TextProperties::VAlign vAlign);

  void render(const Camera& cam);
  void compileShaders();
  void uploadVbo();
};

TextLabelBase::RenderImpl::RenderImpl()
  : vertices(4), shadersInvalid(true), textureInvalid(true), vboInvalid(true),
    radius(0.0)
{
  texture.setMinFilter(Texture2D::Nearest);
  texture.setMagFilter(Texture2D::Nearest);
  texture.setWrappingS(Texture2D::ClampToEdge);
  texture.setWrappingT(Texture2D::ClampToEdge);
}

void TextLabelBase::RenderImpl::setTextureData(
  const Array<unsigned char>& buffer, const Vector2i& dimensions)
{
  // Calculate texture coordinates. This centers each texel on a pixel:
  const Vector2f dimsF(dimensions.cast<float>());
  const Vector2f denoms(dimsF * 2.f);
  const float uMin = 1.f / denoms[0];
  const float vMin = 1.f / denoms[1];
  const float uMax = ((2.f * dimsF[0]) - 1.f) / denoms[0];
  const float vMax = ((2.f * dimsF[1]) - 1.f) / denoms[1];
  vertices[0].tcoord = Vector2f(uMin, vMin);
  vertices[1].tcoord = Vector2f(uMax, vMin);
  vertices[2].tcoord = Vector2f(uMin, vMax);
  vertices[3].tcoord = Vector2f(uMax, vMax);
  vboInvalid = true;

  // Upload texture
  texture.upload(buffer, dimensions, Texture2D::IncomingRGBA,
                 Texture2D::InternalRGBA);
  textureInvalid = false;
}

void TextLabelBase::RenderImpl::setOffsets(const Vector2i& dimensions,
                                           TextProperties::HAlign hAlign,
                                           TextProperties::VAlign vAlign)
{
  Vector2i& tl = vertices[0].offset;
  Vector2i& tr = vertices[1].offset;
  Vector2i& bl = vertices[2].offset;
  Vector2i& br = vertices[3].offset;

  switch (hAlign) {
    case TextProperties::HLeft:
      bl.x() = tl.x() = 0;
      br.x() = tr.x() = dimensions.x() - 1;
      break;
    case TextProperties::HCenter:
      bl.x() = tl.x() = -(dimensions.x() / 2);
      br.x() = tr.x() = dimensions.x() / 2 + (dimensions.x() % 2 == 0 ? 1 : 0);
      break;
    case TextProperties::HRight:
      bl.x() = tl.x() = -(dimensions.x() - 1);
      br.x() = tr.x() = 0;
      break;
  }

  switch (vAlign) {
    case TextProperties::VTop:
      bl.y() = br.y() = -(dimensions.y() - 1);
      tl.y() = tr.y() = 0;
      break;
    case TextProperties::VCenter:
      bl.y() = br.y() = -(dimensions.y() / 2);
      tl.y() = tr.y() = dimensions.y() / 2 - (dimensions.y() % 2 == 0 ? 1 : 0);
      break;
    case TextProperties::VBottom:
      bl.y() = br.y() = 0;
      tl.y() = tr.y() = dimensions.y() - 1;
      break;
  }

  vboInvalid = true;
}

void TextLabelBase::RenderImpl::render(const Camera& cam)
{
  // The texture should be valid at this point.
  if (textureInvalid) {
    std::cerr << "Unable to render text label -- no texture set. "
                 "This is a bug."
              << std::endl;
    return;
  }

  // Prepare GL
  if (shadersInvalid)
    compileShaders();
  if (vboInvalid)
    uploadVbo();

  const Matrix4f mv(cam.modelView().matrix());
  const Matrix4f proj(cam.projection().matrix());
  const Vector2i vpDims(cam.width(), cam.height());

  // Bind vbo
  if (!vbo.bind()) {
    std::cerr << "Error while binding TextLabelBase VBO: " << vbo.error()
              << std::endl;
    return;
  }

  // Setup shaders
  if (!shaderProgram.bind() || !shaderProgram.setUniformValue("mv", mv) ||
      !shaderProgram.setUniformValue("proj", proj) ||
      !shaderProgram.setUniformValue("vpDims", vpDims) ||
      !shaderProgram.setUniformValue("anchor", anchor) ||
      !shaderProgram.setUniformValue("radius", radius) ||
      !shaderProgram.setTextureSampler("texture", texture) ||

      !shaderProgram.enableAttributeArray("offset") ||
      !shaderProgram.useAttributeArray("offset", PackedVertex::offsetOffset(),
                                       sizeof(PackedVertex), IntType, 2,
                                       ShaderProgram::NoNormalize) ||

      !shaderProgram.enableAttributeArray("texCoord") ||
      !shaderProgram.useAttributeArray("texCoord", PackedVertex::tcoordOffset(),
                                       sizeof(PackedVertex), FloatType, 2,
                                       ShaderProgram::NoNormalize)) {
    std::cerr << "Error setting up TextLabelBase shader program: "
              << shaderProgram.error() << std::endl;
    vbo.release();
    shaderProgram.release();
    return;
  }

  // Draw texture
  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

  // Release resources:
  shaderProgram.disableAttributeArray("texCoords");
  shaderProgram.disableAttributeArray("offset");
  shaderProgram.release();
  vbo.release();
}

void TextLabelBase::RenderImpl::compileShaders()
{
  vertexShader.setType(Shader::Vertex);
  vertexShader.setSource(textlabelbase_vs);
  if (!vertexShader.compile()) {
    std::cerr << vertexShader.error() << std::endl;
    return;
  }

  fragmentShader.setType(Shader::Fragment);
  fragmentShader.setSource(textlabelbase_fs);
  if (!fragmentShader.compile()) {
    std::cerr << fragmentShader.error() << std::endl;
    return;
  }

  shaderProgram.attachShader(vertexShader);
  shaderProgram.attachShader(fragmentShader);
  if (!shaderProgram.link()) {
    std::cerr << shaderProgram.error() << std::endl;
    return;
  }

  shadersInvalid = false;
}

void TextLabelBase::RenderImpl::uploadVbo()
{
  if (!vbo.upload(vertices, BufferObject::ArrayBuffer))
    std::cerr << "TextLabelBase VBO error: " << vbo.error() << std::endl;
  else
    vboInvalid = false;
}

TextLabelBase::TextLabelBase() : m_render(new RenderImpl)
{
}

TextLabelBase::TextLabelBase(const TextLabelBase& other)
  : Drawable(other), m_text(other.m_text),
    m_textProperties(other.m_textProperties),
    m_imageDimensions(other.m_imageDimensions), m_imageRgba(other.m_imageRgba),
    m_render(new RenderImpl)
{
}

TextLabelBase::~TextLabelBase()
{
  delete m_render;
}

void TextLabelBase::render(const Camera& camera)
{
  m_render->render(camera);
}

void TextLabelBase::buildTexture(const TextRenderStrategy& tren)
{
  if (!m_render->textureInvalid)
    return;

  // Determine texture size and allocate buffer
  int bbox[4];
  tren.boundingBox(m_text, m_textProperties, bbox);
  const Vector2i newDims(bbox[1] - bbox[0] + 1, bbox[3] - bbox[2] + 1);
  if (newDims != m_imageDimensions) {
    m_imageDimensions = newDims;
    m_render->setOffsets(m_imageDimensions, m_textProperties.hAlign(),
                         m_textProperties.vAlign());
  }
  const size_t bytesPerPixel = 4; // RGBA
  m_imageRgba.resize(
    static_cast<size_t>(m_imageDimensions[0] * m_imageDimensions[1]) *
    bytesPerPixel);

  // Render the text to the buffer
  if (m_imageRgba.size() > 0) {
    tren.render(m_text, m_textProperties, m_imageRgba.data(),
                m_imageDimensions);
  }

  m_render->setTextureData(m_imageRgba, m_imageDimensions);
}

void TextLabelBase::setText(const std::string& str)
{
  if (str != m_text) {
    m_text = str;
    m_render->textureInvalid = true;
  }
}

const std::string& TextLabelBase::text() const
{
  return m_text;
}

void TextLabelBase::setTextProperties(const TextProperties& tprop)
{
  if (tprop != m_textProperties) {
    m_textProperties = tprop;
    m_render->textureInvalid = true;
    m_render->setOffsets(m_imageDimensions, tprop.hAlign(), tprop.vAlign());
  }
}

const TextProperties& TextLabelBase::textProperties() const
{
  return m_textProperties;
}

void TextLabelBase::resetTexture()
{
  m_render->textureInvalid = true;
}

void TextLabelBase::setAnchorInternal(const Vector3f& a)
{
  m_render->anchor = a;
}

Vector3f TextLabelBase::getAnchorInternal() const
{
  return m_render->anchor;
}

void TextLabelBase::setRadiusInternal(float radius)
{
  m_render->radius = radius;
}

float TextLabelBase::getRadiusInternal() const
{
  return m_render->radius;
}

void TextLabelBase::markDirty()
{
  m_render->shadersInvalid = true;
  m_render->textureInvalid = true;
  m_render->vboInvalid = true;
}

} // namespace Rendering
} // namespace Avogadro

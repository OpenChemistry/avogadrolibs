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

namespace Avogadro {
namespace Rendering {

namespace {
GLint convertFilterOptionToGL(Texture2D::FilterOption opt)
{
  switch (opt) {
    case Texture2D::Nearest:
      return GL_NEAREST;
    case Texture2D::Linear:
      return GL_LINEAR;
    default:
      return -1;
  }
}

Texture2D::FilterOption convertFilterOptionFromGL(GLint opt)
{
  switch (opt) {
    case GL_NEAREST:
      return Texture2D::Nearest;
    case GL_LINEAR:
      return Texture2D::Linear;
    default:
      return Texture2D::InvalidFilter;
  }
}

GLint convertWrappingOptionToGL(Texture2D::WrappingOption opt)
{
  switch (opt) {
    case Texture2D::ClampToEdge:
      return GL_CLAMP_TO_EDGE;
    case Texture2D::MirroredRepeat:
      return GL_MIRRORED_REPEAT;
    case Texture2D::Repeat:
      return GL_REPEAT;
    default:
      return -1;
  }
}

Texture2D::WrappingOption convertWrappingOptionFromGL(GLint opt)
{
  switch (opt) {
    case GL_CLAMP_TO_EDGE:
      return Texture2D::ClampToEdge;
    case GL_MIRRORED_REPEAT:
      return Texture2D::MirroredRepeat;
    case GL_REPEAT:
      return Texture2D::Repeat;
    default:
      return Texture2D::InvalidWrapping;
  }
}

GLint convertInternalFormatToGL(Texture2D::InternalFormat fmt)
{
  switch (fmt) {
    case Texture2D::InternalDepth:
      return GL_DEPTH_COMPONENT;
    case Texture2D::InternalDepthStencil:
      return GL_DEPTH_STENCIL;
    case Texture2D::InternalR:
      return GL_RED;
    case Texture2D::InternalRG:
      return GL_RG;
    case Texture2D::InternalRGB:
      return GL_RGB;
    case Texture2D::InternalRGBA:
      return GL_RGBA;
    default:
      return -1;
  }
}

GLint convertIncomingFormatToGL(Texture2D::IncomingFormat fmt)
{
  switch (fmt) {
    case Texture2D::IncomingR:
      return GL_RED;
    case Texture2D::IncomingRG:
      return GL_RG;
    case Texture2D::IncomingRGB:
      return GL_RGB;
    case Texture2D::IncomingBGR:
      return GL_BGR;
    case Texture2D::IncomingRGBA:
      return GL_RGBA;
    case Texture2D::IncomingBGRA:
      return GL_BGRA;
    case Texture2D::IncomingDepth:
      return GL_DEPTH_COMPONENT;
    case Texture2D::IncomingDepthStencil:
      return GL_DEPTH_STENCIL;
    default:
      return -1;
  }
}

GLenum convertTypeToGL(Type type)
{
  switch (type) {
    case CharType:
      return GL_BYTE;
    case UCharType:
      return GL_UNSIGNED_BYTE;
    case ShortType:
      return GL_SHORT;
    case UShortType:
      return GL_UNSIGNED_SHORT;
    case IntType:
      return GL_INT;
    case UIntType:
      return GL_UNSIGNED_INT;
    case FloatType:
      return GL_FLOAT;
    case DoubleType:
      return GL_DOUBLE;
    default:
      return 0;
  }
}

} // end anon namespace

class Texture2D::Private
{
public:
  Private() : textureId(0) {}
  ~Private()
  {
    if (textureId > 0)
      glDeleteTextures(1, &textureId);
  }

  mutable GLuint textureId;
};

Texture2D::Texture2D() : d(new Private)
{
}

Texture2D::~Texture2D()
{
  delete d;
}

Index Texture2D::handle() const
{
  return static_cast<Index>(d->textureId);
}

void Texture2D::setMinFilter(Texture2D::FilterOption opt)
{
  Index old = pushTexture();
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER,
                  convertFilterOptionToGL(opt));
  popTexture(old);
}

Texture2D::FilterOption Texture2D::minFilter() const
{
  Index old = pushTexture();
  GLint result;
  glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, &result);
  popTexture(old);

  return convertFilterOptionFromGL(result);
}

void Texture2D::setMagFilter(Texture2D::FilterOption opt)
{
  Index old = pushTexture();
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER,
                  convertFilterOptionToGL(opt));
  popTexture(old);
}

Texture2D::FilterOption Texture2D::magFilter() const
{
  Index old = pushTexture();
  GLint result;
  glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, &result);
  popTexture(old);

  return convertFilterOptionFromGL(result);
}

void Texture2D::setWrappingS(Texture2D::WrappingOption opt)
{
  Index old = pushTexture();
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                  convertWrappingOptionToGL(opt));
  popTexture(old);
}

Texture2D::WrappingOption Texture2D::wrappingS() const
{
  Index old = pushTexture();
  GLint result;
  glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, &result);
  popTexture(old);

  return convertWrappingOptionFromGL(result);
}

void Texture2D::setWrappingT(Texture2D::WrappingOption opt)
{
  Index old = pushTexture();
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                  convertWrappingOptionToGL(opt));
  popTexture(old);
}

Texture2D::WrappingOption Texture2D::wrappingT() const
{
  Index old = pushTexture();
  GLint result;
  glGetTexParameteriv(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, &result);
  popTexture(old);

  return convertWrappingOptionFromGL(result);
}

bool Texture2D::bind() const
{
  return pushTexture() != MaxIndex;
}

bool Texture2D::release() const
{
  popTexture(0);
  return true;
}

bool Texture2D::uploadInternal(const void* buffer, const Vector2i& dims,
                               Texture2D::IncomingFormat dataFormat,
                               Avogadro::Type dataType,
                               Texture2D::InternalFormat internalFormat)
{
  // The dataType has already been validated.
  Index old = pushTexture();
  glTexImage2D(GL_TEXTURE_2D, 0, convertInternalFormatToGL(internalFormat),
               dims[0], dims[1], 0, convertIncomingFormatToGL(dataFormat),
               convertTypeToGL(dataType),
               static_cast<GLvoid*>(const_cast<void*>(buffer)));
  popTexture(old);
  return true;
}

Index Texture2D::pushTexture() const
{
  GLint currentHandle;
  glGetIntegerv(GL_TEXTURE_BINDING_2D, &currentHandle);

  if (d->textureId == 0) {
    if (!const_cast<Texture2D*>(this)->generateTextureHandle())
      return MaxIndex;
  }

  glBindTexture(GL_TEXTURE_2D, d->textureId);

  return static_cast<Index>(currentHandle);
}

void Texture2D::popTexture(Index id) const
{
  glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(id));
}

bool Texture2D::generateTextureHandle()
{
  if (d->textureId > 0) {
    m_error = "Refusing to overwrite existing texture handle.";
    return false;
  }

  glGenTextures(1, &d->textureId);

  if (d->textureId == 0) {
    m_error = "Error generating texture handle.";
    return false;
  }

  // Set up defaults to match the documentation:
  setMinFilter(Linear);
  setMagFilter(Linear);
  setWrappingS(Repeat);
  setWrappingT(Repeat);

  return true;
}

} // namespace Rendering
} // namespace Avogadro

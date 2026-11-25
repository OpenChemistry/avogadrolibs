/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "texture2d.h"

#include "avogadrogl.h"

namespace Avogadro::Rendering {

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
#ifdef __EMSCRIPTEN__
      return -1;
#else
      return GL_BGR;
#endif
    case Texture2D::IncomingRGBA:
      return GL_RGBA;
    case Texture2D::IncomingBGRA:
#ifdef __EMSCRIPTEN__
      return -1;
#else
      return GL_BGRA;
#endif
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
#ifndef __EMSCRIPTEN__
    case DoubleType:
      return GL_DOUBLE;
#endif
    default:
      return 0;
  }
}

} // namespace

class Texture2D::Private
{
public:
  Private() = default;
  ~Private()
  {
    if (textureId > 0)
      glDeleteTextures(1, &textureId);
  }

  mutable GLuint textureId = 0;
  Texture2D::FilterOption minFilter = Texture2D::Linear;
  Texture2D::FilterOption magFilter = Texture2D::Linear;
  Texture2D::WrappingOption wrappingS = Texture2D::Repeat;
  Texture2D::WrappingOption wrappingT = Texture2D::Repeat;
};

Texture2D::Texture2D() : d(new Private), m_dirty(true) {}

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
  const GLint glOpt = convertFilterOptionToGL(opt);
  if (glOpt == -1)
    return;
  d->minFilter = opt;
  if (d->textureId != 0) {
    Index old = pushTexture();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, glOpt);
    popTexture(old);
  }
}

Texture2D::FilterOption Texture2D::minFilter() const
{
  return d->minFilter;
}

void Texture2D::setMagFilter(Texture2D::FilterOption opt)
{
  const GLint glOpt = convertFilterOptionToGL(opt);
  if (glOpt == -1)
    return;
  d->magFilter = opt;
  if (d->textureId != 0) {
    Index old = pushTexture();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, glOpt);
    popTexture(old);
  }
}

Texture2D::FilterOption Texture2D::magFilter() const
{
  return d->magFilter;
}

void Texture2D::setWrappingS(Texture2D::WrappingOption opt)
{
  const GLint glOpt = convertWrappingOptionToGL(opt);
  if (glOpt == -1)
    return;
  d->wrappingS = opt;
  if (d->textureId != 0) {
    Index old = pushTexture();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, glOpt);
    popTexture(old);
  }
}

Texture2D::WrappingOption Texture2D::wrappingS() const
{
  return d->wrappingS;
}

void Texture2D::setWrappingT(Texture2D::WrappingOption opt)
{
  const GLint glOpt = convertWrappingOptionToGL(opt);
  if (glOpt == -1)
    return;
  d->wrappingT = opt;
  if (d->textureId != 0) {
    Index old = pushTexture();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, glOpt);
    popTexture(old);
  }
}

Texture2D::WrappingOption Texture2D::wrappingT() const
{
  return d->wrappingT;
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
  const GLint incomingFormat = convertIncomingFormatToGL(dataFormat);
  if (incomingFormat == -1) {
    m_error = "Unsupported incoming texture format; WebGL requires RGB or RGBA "
              "instead of BGR or BGRA.";
    return false;
  }
  const GLint storageFormat = convertInternalFormatToGL(internalFormat);
  const GLenum type = convertTypeToGL(dataType);
  if (storageFormat == -1 || type == 0) {
    m_error = "Unsupported texture storage format or data type.";
    return false;
  }
  Index old = pushTexture();
  if (old == MaxIndex)
    return false;
  glTexImage2D(GL_TEXTURE_2D, 0, storageFormat, dims[0], dims[1], 0,
               incomingFormat, type,
               static_cast<GLvoid*>(const_cast<void*>(buffer)));
  popTexture(old);
  m_dirty = false;
  return true;
}

Index Texture2D::pushTexture() const
{
  GLint currentHandle = 0;
  glGetIntegerv(GL_TEXTURE_BINDING_2D, &currentHandle);

  if (d->textureId == 0) {
    if (!const_cast<Texture2D*>(this)->generateTextureHandle()) {
      glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(currentHandle));
      return MaxIndex;
    }
  } else {
    glBindTexture(GL_TEXTURE_2D, d->textureId);
  }

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

  // Bind and apply cached filter/wrap options (defaults or values set before
  // a GL context existed).
  glBindTexture(GL_TEXTURE_2D, d->textureId);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER,
                  convertFilterOptionToGL(d->minFilter));
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER,
                  convertFilterOptionToGL(d->magFilter));
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                  convertWrappingOptionToGL(d->wrappingS));
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                  convertWrappingOptionToGL(d->wrappingT));

  return true;
}

} // namespace Avogadro::Rendering

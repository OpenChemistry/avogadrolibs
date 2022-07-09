/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "textlabel3d.h"

#include "visitor.h"

namespace Avogadro::Rendering {

TextLabel3D::TextLabel3D()
{
  setRenderPass(TranslucentPass);
}

TextLabel3D::~TextLabel3D()
{
}

void TextLabel3D::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void TextLabel3D::setAnchor(const Vector3f& position)
{
  setAnchorInternal(position);
}

Vector3f TextLabel3D::anchor() const
{
  return getAnchorInternal();
}

void TextLabel3D::setRadius(float r)
{
  setRadiusInternal(r);
}

float TextLabel3D::radius() const
{
  return getRadiusInternal();
}

} // namespace Avogadro

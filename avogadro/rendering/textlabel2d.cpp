/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "textlabel2d.h"

#include "visitor.h"

namespace Avogadro::Rendering {

TextLabel2D::TextLabel2D()
{
  setRenderPass(Rendering::Overlay2DPass);
}

TextLabel2D::~TextLabel2D()
{
}

void TextLabel2D::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void TextLabel2D::setAnchor(const Vector2i& windowCoords)
{
  setAnchorInternal(Vector3f(static_cast<float>(windowCoords.x()),
                             static_cast<float>(windowCoords.y()), 0.f));
}

Vector2i TextLabel2D::anchor() const
{
  return getAnchorInternal().head<2>().cast<int>();
}

} // namespace Avogadro

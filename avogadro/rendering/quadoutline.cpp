/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quadoutline.h"

using Avogadro::Core::Array;

namespace Avogadro::Rendering {

void QuadOutline::setQuad(const Vector3f& topLeft, const Vector3f& topRight,
                          const Vector3f& bottomLeft,
                          const Vector3f& bottomRight, float lineWidth)
{
  Array<Vector3f> verts(5);
  verts[0] = topLeft;
  verts[1] = topRight;
  verts[2] = bottomRight;
  verts[3] = bottomLeft;
  verts[4] = topLeft;

  clear();
  addLineStrip(verts, lineWidth);
}

} // End namespace Avogadro::Rendering

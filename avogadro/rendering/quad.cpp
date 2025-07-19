/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "quad.h"

using Avogadro::Core::Array;

namespace Avogadro::Rendering {

void Quad::setQuad(const Vector3f& topLeft, const Vector3f& topRight,
                   const Vector3f& bottomLeft, const Vector3f& bottomRight)
{
  const Vector3f bottom = bottomRight - bottomLeft;
  const Vector3f left = topLeft - bottomLeft;
  const Vector3f normal = bottom.cross(left).normalized();
  Array<Vector3f> norms(4, normal);

  Array<Vector3f> verts(4);
  verts[0] = topLeft;
  verts[1] = topRight;
  verts[2] = bottomLeft;
  verts[3] = bottomRight;

  Array<unsigned int> indices(6);
  indices[0] = 0;
  indices[1] = 1;
  indices[2] = 2;
  indices[3] = 2;
  indices[4] = 1;
  indices[5] = 3;

  clear();
  addVertices(verts, norms);
  addTriangles(indices);
}

} // End namespace Avogadro::Rendering

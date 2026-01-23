/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vertexarrayobject.h"

#include "avogadrogl.h"

namespace Avogadro::Rendering {

VertexArrayObject::VertexArrayObject()
{
  glGenVertexArrays(1, &m_handle);
}

VertexArrayObject::~VertexArrayObject()
{
  if (m_handle != 0)
    glDeleteVertexArrays(1, &m_handle);
}

bool VertexArrayObject::bind()
{
  if (m_handle == 0)
    return false;
  glBindVertexArray(m_handle);
  return true;
}

void VertexArrayObject::release()
{
  glBindVertexArray(0);
}

} // namespace Avogadro::Rendering

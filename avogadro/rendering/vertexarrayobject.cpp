/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vertexarrayobject.h"

#include "avogadrogl.h"

namespace Avogadro::Rendering {

VertexArrayObject::VertexArrayObject() : m_handle(0)
{
  // Lazy initialization - VAO will be created on first bind()
  // This allows the object to be constructed before GL context exists
}

VertexArrayObject::~VertexArrayObject()
{
  if (m_handle != 0)
    glDeleteVertexArrays(1, &m_handle);
}

bool VertexArrayObject::bind()
{
  // Lazy initialization - create VAO on first bind when GL context exists
  if (m_handle == 0)
    glGenVertexArrays(1, &m_handle);
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

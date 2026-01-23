/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_VERTEXARRAYOBJECT_H
#define AVOGADRO_RENDERING_VERTEXARRAYOBJECT_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace Rendering {

/**
 * @class VertexArrayObject vertexarrayobject.h
 * <avogadro/rendering/vertexarrayobject.h>
 * @brief Vertex Array Object to capture vertex attribute state.
 *
 * This class wraps an OpenGL VAO, which captures the state of vertex
 * attribute bindings. Required for OpenGL 3.2+ core profile.
 *
 * The VAO handle is lazily created on first bind(), allowing the object
 * to be constructed before the OpenGL context is initialized.
 *
 * Usage pattern:
 *   // During setup (when buffers change):
 *   vao.bind();
 *   vbo.bind();
 *   ibo.bind();
 *   // set up vertex attribute pointers
 *   vao.release();
 *
 *   // During render:
 *   vao.bind();
 *   glDrawElements(...);
 *   vao.release();
 */
class AVOGADRORENDERING_EXPORT VertexArrayObject
{
public:
  VertexArrayObject();
  ~VertexArrayObject();

  // Non-copyable (OpenGL resource)
  VertexArrayObject(const VertexArrayObject&) = delete;
  VertexArrayObject& operator=(const VertexArrayObject&) = delete;

  /** Bind the VAO, making it active for attribute setup or rendering. */
  bool bind();

  /** Unbind the VAO. */
  void release();

  /** Get the OpenGL handle. Returns 0 if not yet created. */
  Index handle() const { return static_cast<Index>(m_handle); }

private:
  unsigned int m_handle = 0;
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_VERTEXARRAYOBJECT_H

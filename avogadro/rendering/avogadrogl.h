/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_AVOGADROGL_H
#define AVOGADRO_RENDERING_AVOGADROGL_H

/**
 * GLEW should always be in the same place, but Apple likes to move gl.h.
 * This header should be used instead of including the GL headers directly
 * in order to work around different layouts.
 */

#ifdef __EMSCRIPTEN__
#include <GLES3/gl3.h>
#elif defined(__APPLE__)
#include <OpenGL/gl.h>
#else
#include <GL/glew.h>
#include <GL/gl.h>
#endif

#endif // AVOGADRO_RENDERING_AVOGADROGL_H

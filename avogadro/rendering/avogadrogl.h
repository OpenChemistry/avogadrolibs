/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_RENDERING_AVOGADROGL_H
#define AVOGADRO_RENDERING_AVOGADROGL_H

/**
 * GLEW should always be in the same place, but Apple likes to move gl.h.
 * This header should be used instead of including the GL headers directly
 * in order to work around different layouts.
 */

#include <GL/glew.h>

#ifdef __APPLE__
#include <OpenGL/gl.h>
#else
#include <GL/gl.h>
#endif

#endif // AVOGADRO_RENDERING_AVOGADROGL_H

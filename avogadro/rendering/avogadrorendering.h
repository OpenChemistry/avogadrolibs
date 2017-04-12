/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRORENDERING_H
#define AVOGADRORENDERING_H

namespace Avogadro {
namespace Rendering {

/**
 * @brief The RenderPass enum is used to identify different stages in
 * multipass rendering.
 */
enum RenderPass
{
  /**
   * Default value -- no rendering is currently happening.
   */
  NotRendering = 0,
  /**
   * Opaque geometry is being drawn. Alpha blending disabled, depth testing is
   * enabled.
   */
  OpaquePass,
  /**
   * Translucent geometry is being drawn. Depth testing is disabled, and alpha
   * blending is enabled using the equivalent of the OpenGL call
   * @code glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA) @endcode
   */
  TranslucentPass,
  /**
   * 3D geometry is being drawn over the Opaque and Translucent rendering.
   * Depth testing is disabled, and alpha blending is enabled using the
   * equivalent of the OpenGL call
   * @code glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA) @endcode
   */
  Overlay3DPass,
  /**
   * 2D drawables are being rendered over the 3D scene. The
   * modelview matrix is identity, and the projection matrix is configured to
   * an orthographic projection that matches the viewport. Valid Z values are
   * [-1, 1], and the origin is in the bottom-left corner. Depth testing is
   * disabled, and alpha blending is performed the same as in TranslucentPass.
   */
  Overlay2DPass
};

} // end namespace Rendering
} // end namespace Avogadro

#endif // AVOGADRORENDERING_H

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

#ifndef AVOGADRO_RENDERING_GLRENDERVISITOR_H
#define AVOGADRO_RENDERING_GLRENDERVISITOR_H

#include "visitor.h"

#include "camera.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class GLRenderVisitor glrendervisitor.h <avogadro/rendering/glrendervisitor.h>
 * @brief Visitor that takes care of rendering the scene.
 * @author Marcus D. Hanwell
 *
 * This visitor will render elements in the scene.
 */

class AVOGADRORENDERING_EXPORT GLRenderVisitor : public Visitor
{
public:
  explicit GLRenderVisitor(const Camera &camera = Camera());
  ~GLRenderVisitor() AVO_OVERRIDE;

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node &) AVO_OVERRIDE { return; }
  void visit(GroupNode &) AVO_OVERRIDE { return; }
  void visit(GeometryNode &) AVO_OVERRIDE { return; }
  void visit(Drawable &) AVO_OVERRIDE;
  void visit(SphereGeometry &) AVO_OVERRIDE;
  void visit(CylinderGeometry &) AVO_OVERRIDE;
  void visit(MeshGeometry &) AVO_OVERRIDE;

  void setCamera(const Camera &camera_) { m_camera = camera_; }
  Camera camera() const { return m_camera; }

private:
  Camera m_camera;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GLRENDERVISITOR_H

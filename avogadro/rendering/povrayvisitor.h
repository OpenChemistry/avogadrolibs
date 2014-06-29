/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_RENDERING_POVRAYVISITOR_H
#define AVOGADRO_RENDERING_POVRAYVISITOR_H

#include "visitor.h"

#include "avogadrorendering.h"
#include "camera.h"

#include <string>

namespace Avogadro {
namespace Rendering {

/**
 * @class POVRayVisitor povrayvisitor.h <avogadro/rendering/povrayvisitor.h>
 * @brief Visitor that visits scene elements and creates a POV-Ray input file.
 *
 * This visitor will render elements in the scene to a text file that contains
 * elements that can be rendered by POV-Ray.
 */

class AVOGADRORENDERING_EXPORT POVRayVisitor : public Visitor
{
public:
  POVRayVisitor(const Camera &camera);
  ~POVRayVisitor() AVO_OVERRIDE;

  void begin();
  void end();

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node &) AVO_OVERRIDE { return; }
  void visit(GroupNode &) AVO_OVERRIDE { return; }
  void visit(GeometryNode &) AVO_OVERRIDE { return; }
  void visit(Drawable &) AVO_OVERRIDE;
  void visit(SphereGeometry &) AVO_OVERRIDE;
  void visit(AmbientOcclusionSphereGeometry &) AVO_OVERRIDE;
  void visit(CylinderGeometry &) AVO_OVERRIDE;
  void visit(MeshGeometry &) AVO_OVERRIDE;
  void visit(TextLabel2D &) AVO_OVERRIDE { return; }
  void visit(TextLabel3D &) AVO_OVERRIDE { return; }
  void visit(LineStripGeometry &geometry) AVO_OVERRIDE;

  void setCamera(const Camera &c) { m_camera = c; }
  Camera camera() const { return m_camera; }

  void setBackgroundColor(const Vector3ub &c) { m_backgroundColor = c; }
  void setAmbientColor(const Vector3ub &c) { m_ambientColor = c; }
  void setAspectRatio(float ratio) { m_aspectRatio = ratio; }

private:
  Camera m_camera;
  Vector3ub m_backgroundColor;
  Vector3ub m_ambientColor;
  float m_aspectRatio;

  std::string m_sceneData;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_POVRAYVISITOR_H

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
  POVRayVisitor(const Camera& camera);
  ~POVRayVisitor() override;

  void begin();
  std::string end();

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node&) override { return; }
  void visit(GroupNode&) override { return; }
  void visit(GeometryNode&) override { return; }
  void visit(Drawable&) override;
  void visit(SphereGeometry&) override;
  void visit(AmbientOcclusionSphereGeometry&) override;
  void visit(CurveGeometry&) override { return; }
  void visit(CylinderGeometry&) override;
  void visit(MeshGeometry&) override;
  void visit(TextLabel2D&) override { return; }
  void visit(TextLabel3D&) override { return; }
  void visit(LineStripGeometry& geometry) override;

  void setCamera(const Camera& c) { m_camera = c; }
  Camera camera() const { return m_camera; }

  void setBackgroundColor(const Vector3ub& c) { m_backgroundColor = c; }
  void setAmbientColor(const Vector3ub& c) { m_ambientColor = c; }
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

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_PLYVISITOR_H
#define AVOGADRO_RENDERING_PLYVISITOR_H

#include "visitor.h"

#include "avogadrorendering.h"
#include "spheregeometry.h"
#include "cylindergeometry.h"
#include "ambientocclusionspheregeometry.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "camera.h"
#include <string>
#include <vector>
#include <iostream>
#include <ostream>

namespace Avogadro {
namespace Rendering {

/**
 * @class PLYVisitor plyvisitor.h <avogadro/rendering/plyvisitor.h>
 * @brief Visitor that visits scene elements and creates a PLY input file.
 *
 * This visitor will render elements in the scene to a text file that contains
 * elements that can be rendered as PLY.
 */

class AVOGADRORENDERING_EXPORT PLYVisitor : public Visitor
{
public:
  explicit PLYVisitor(const Camera& camera);
  ~PLYVisitor() override;

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
  long m_vertexCount = 0;
  long m_faceCount = 0;
  std::string m_sceneVertices = "";
  std::string m_sceneFaces = "";

  void visitSphereIcosphereRecursionMethod(const SphereColor& geometry,
                                           unsigned int subdivisions);
  void visitCylinderLateralMethod(const CylinderColor& geometry,
                                  unsigned int lateralFaces);
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_PLYVISITOR_H

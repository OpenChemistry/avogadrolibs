/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_VISITOR_H
#define AVOGADRO_RENDERING_VISITOR_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace Rendering {

class ArrowGeometry;
class CylinderGeometry;
class DashedLineGeometry;
class Drawable;
class GeometryNode;
class GroupNode;
class LineStripGeometry;
class MeshGeometry;
class Node;
class SphereGeometry;
class TextLabel2D;
class TextLabel3D;
class CurveGeometry;
class VolumeGeometry;
class WideLineGeometry;

/**
 * @class Visitor visitor.h <avogadro/rendering/visitor.h>
 * @brief The Visitor class is the base class for all Node visitors.
 * @author Marcus D. Hanwell
 *
 * The Visitor class is the base class for visitors to Node objects in the
 * Scene, providing common API and functionality.
 */

class AVOGADRORENDERING_EXPORT Visitor
{
public:
  Visitor();
  virtual ~Visitor();

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  virtual void visit(Node&) {}
  virtual void visit(GroupNode&) {}
  virtual void visit(GeometryNode&) {}
  virtual void visit(Drawable&) {}
  virtual void visit(SphereGeometry&) {}
  virtual void visit(CurveGeometry&) {}
  virtual void visit(CylinderGeometry&) {}
  virtual void visit(MeshGeometry&) {}
  virtual void visit(TextLabel2D&) {}
  virtual void visit(TextLabel3D&) {}
  virtual void visit(LineStripGeometry&) {}
  virtual void visit(WideLineGeometry&) {}
  virtual void visit(DashedLineGeometry&) {}
  virtual void visit(ArrowGeometry&) {}
  virtual void visit(VolumeGeometry&) {}
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VISITOR_H

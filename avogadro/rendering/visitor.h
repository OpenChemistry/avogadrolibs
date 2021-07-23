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

#ifndef AVOGADRO_RENDERING_VISITOR_H
#define AVOGADRO_RENDERING_VISITOR_H

#include "avogadrorenderingexport.h"
#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace Rendering {

class CylinderGeometry;
class Drawable;
class GeometryNode;
class GroupNode;
class LineStripGeometry;
class MeshGeometry;
class Node;
class SphereGeometry;
class TextLabel2D;
class TextLabel3D;
class AmbientOcclusionSphereGeometry;
class CurveGeometry;

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
  virtual void visit(Node&) { return; }
  virtual void visit(GroupNode&) { return; }
  virtual void visit(GeometryNode&) { return; }
  virtual void visit(Drawable&) { return; }
  virtual void visit(SphereGeometry&) { return; }
  virtual void visit(AmbientOcclusionSphereGeometry&) { return; }
  virtual void visit(CurveGeometry&) { return; }
  virtual void visit(CylinderGeometry&) { return; }
  virtual void visit(MeshGeometry&) { return; }
  virtual void visit(TextLabel2D&) { return; }
  virtual void visit(TextLabel3D&) { return; }
  virtual void visit(LineStripGeometry&) { return; }
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_VISITOR_H

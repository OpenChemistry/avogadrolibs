/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_TRANSFORMNODE_H
#define AVOGADRO_RENDERING_TRANSFORMNODE_H

#include "groupnode.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class TransformNode transformnode.h <avogadro/rendering/transformnode.h>
 * @brief The TransformNode class applies a transform to all child nodes.
 * @author Marcus D. Hanwell
 *
 * @todo This is currently a stub and does nothing.
 */

class AVOGADRORENDERING_EXPORT TransformNode : public GroupNode
{
public:
  explicit TransformNode(GroupNode* parent = nullptr);
  ~TransformNode() override;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_TRANSFORMNODE_H

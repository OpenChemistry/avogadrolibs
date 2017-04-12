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

#include "transformnode.h"

namespace Avogadro {
namespace Rendering {

TransformNode::TransformNode(GroupNode* p) : GroupNode(p)
{
}

TransformNode::~TransformNode()
{
}

} // End namespace Rendering
} // End namespace Avogadro

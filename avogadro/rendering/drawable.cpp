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

#include "drawable.h"

namespace Avogadro {
namespace Rendering {

Drawable::Drawable() : m_parent(NULL), m_visible(true)
{
}

Drawable::~Drawable()
{
}

void Drawable::render(const Camera &)
{
}

std::multimap<float, Identifier> Drawable::hits(const Vector3f &,
                                                const Vector3f &,
                                                const Vector3f &) const
{
  return std::multimap<float, Identifier>();
}

void Drawable::clear()
{
}

void Drawable::setParent(GeometryNode *parent_)
{
  m_parent = parent_;
}

} // End namespace Rendering
} // End namespace Avogadro

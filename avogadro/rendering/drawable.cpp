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

#include "visitor.h"

namespace Avogadro {
namespace Rendering {

using Core::Array;

Drawable::Drawable()
  : m_parent(nullptr), m_visible(true), m_renderPass(OpaquePass)
{
}

Drawable::Drawable(const Drawable& other)
  : m_parent(other.m_parent), m_visible(other.m_visible),
    m_renderPass(other.m_renderPass), m_identifier(other.m_identifier)
{
}

Drawable::~Drawable()
{
}

void Drawable::accept(Visitor& visitor)
{
  visitor.visit(*this);
}

void Drawable::render(const Camera&)
{
}

std::multimap<float, Identifier> Drawable::hits(const Vector3f&,
                                                const Vector3f&,
                                                const Vector3f&) const
{
  return std::multimap<float, Identifier>();
}

Array<Identifier> Drawable::areaHits(const Frustrum&) const
{
  return Array<Identifier>();
}

void Drawable::clear()
{
}

void Drawable::setParent(GeometryNode* parent_)
{
  m_parent = parent_;
}

} // End namespace Rendering
} // End namespace Avogadro

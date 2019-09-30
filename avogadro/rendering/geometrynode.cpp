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

#include "geometrynode.h"

#include "drawable.h"
#include "visitor.h"

#include <iostream>

namespace Avogadro {
namespace Rendering {

using Core::Array;

GeometryNode::GeometryNode()
{
}

GeometryNode::~GeometryNode()
{
  clearDrawables();
}

void GeometryNode::accept(Visitor& visitor)
{
  visitor.visit(*this);
  for (std::vector<Drawable*>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    (*it)->accept(visitor);
  }
}

void GeometryNode::addDrawable(Drawable* object)
{
  for (std::vector<Drawable*>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    if (*it == object)
      return;
  }
  object->setParent(this);
  m_drawables.push_back(object);
}

bool GeometryNode::removeDrawable(Drawable* object)
{
  if (!object)
    return false;
  for (std::vector<Drawable*>::iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    if (*it == object) {
      (*it)->setParent(nullptr);
      m_drawables.erase(it);
      return true;
    }
  }
  return false;
}

Drawable* GeometryNode::drawable(size_t index)
{
  if (index >= m_drawables.size())
    return nullptr;
  else
    return m_drawables[index];
}

void GeometryNode::clearDrawables()
{
  // Like all good parents, we destroy our children before we go...
  for (std::vector<Drawable*>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    delete (*it);
  }
  m_drawables.clear();
}

void GeometryNode::render(const Camera& camera)
{
  for (std::vector<Drawable*>::iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    if ((*it)->isVisible())
      (*it)->render(camera);
  }
}

std::multimap<float, Identifier> GeometryNode::hits(
  const Vector3f& rayOrigin, const Vector3f& rayEnd,
  const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> result;
  for (std::vector<Drawable*>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    std::multimap<float, Identifier> drawableHits;
    if ((*it)->isVisible())
      drawableHits = (*it)->hits(rayOrigin, rayEnd, rayDirection);
    result.insert(drawableHits.begin(), drawableHits.end());
  }

  return result;
}

Array<Identifier> GeometryNode::areaHits(const Frustrum& f) const
{
  Array<Identifier> result;
  for (auto it = m_drawables.begin(); it != m_drawables.end(); ++it) {
    Array<Identifier> drawableHits;
    if ((*it)->isVisible())
      drawableHits = (*it)->areaHits(f);
    result.insert(result.end(), drawableHits.begin(), drawableHits.end());
  }

  return result;
}

} // End namespace Rendering
} // End namespace Avogadro

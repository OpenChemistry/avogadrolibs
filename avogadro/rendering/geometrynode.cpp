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

namespace Avogadro {
namespace Rendering {

GeometryNode::GeometryNode()
{
}

GeometryNode::~GeometryNode()
{
  clearDrawables();
}

void GeometryNode::addDrawable(Drawable *object)
{
  for (std::vector<Drawable *>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    if (*it == object)
      return;
  }
  object->setParent(this);
  m_drawables.push_back(object);
}

bool GeometryNode::removeDrawable(Drawable *object)
{
  if (!object)
    return false;
  for (std::vector<Drawable *>::iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    if (*it == object) {
      (*it)->setParent(NULL);
      m_drawables.erase(it);
      return true;
    }
  }
  return false;
}

Drawable * GeometryNode::drawable(size_t index)
{
  if (index >= m_drawables.size())
    return NULL;
  else
    return m_drawables[index];
}

void GeometryNode::clearDrawables()
{
  // Like all good parents, we destroy our children before we go...
  for (std::vector<Drawable *>::const_iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    delete (*it);
  }
  m_drawables.clear();
}

void GeometryNode::render(const Camera &camera)
{
  for (std::vector<Drawable *>::iterator it = m_drawables.begin();
       it != m_drawables.end(); ++it) {
    (*it)->render(camera);
  }
}

} // End namespace Rendering
} // End namespace Avogadro

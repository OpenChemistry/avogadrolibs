/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "geometrynode.h"

#include "drawable.h"
#include "visitor.h"

#include <iostream>

namespace Avogadro::Rendering {

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
  for (auto & m_drawable : m_drawables) {
    m_drawable->accept(visitor);
  }
}

void GeometryNode::addDrawable(Drawable* object)
{
  for (auto & m_drawable : m_drawables) {
    if (m_drawable == object)
      return;
  }
  object->setParent(this);
  m_drawables.push_back(object);
}

bool GeometryNode::removeDrawable(Drawable* object)
{
  if (!object)
    return false;
  for (auto it = m_drawables.begin();
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
  for (auto & m_drawable : m_drawables) {
    delete m_drawable;
  }
  m_drawables.clear();
}

void GeometryNode::render(const Camera& camera)
{
  for (auto & m_drawable : m_drawables) {
    if (m_drawable->isVisible())
      m_drawable->render(camera);
  }
}

std::multimap<float, Identifier> GeometryNode::hits(
  const Vector3f& rayOrigin, const Vector3f& rayEnd,
  const Vector3f& rayDirection) const
{
  std::multimap<float, Identifier> result;
  for (auto m_drawable : m_drawables) {
    std::multimap<float, Identifier> drawableHits;
    if (m_drawable->isVisible())
      drawableHits = m_drawable->hits(rayOrigin, rayEnd, rayDirection);
    result.insert(drawableHits.begin(), drawableHits.end());
  }

  return result;
}

Array<Identifier> GeometryNode::areaHits(const Frustrum& f) const
{
  Array<Identifier> result;
  for (auto m_drawable : m_drawables) {
    Array<Identifier> drawableHits;
    if (m_drawable->isVisible())
      drawableHits = m_drawable->areaHits(f);
    result.insert(result.end(), drawableHits.begin(), drawableHits.end());
  }

  return result;
}

} // End namespace Avogadro

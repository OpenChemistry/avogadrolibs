/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "drawable.h"

#include "visitor.h"

namespace Avogadro::Rendering {

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

} // End namespace Avogadro

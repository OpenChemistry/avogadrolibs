/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "variantmap.h"

namespace Avogadro::Core {

VariantMap::VariantMap()
{
}

VariantMap::~VariantMap()
{
}

size_t VariantMap::size() const
{
  return m_map.size();
}

bool VariantMap::isEmpty() const
{
  return m_map.empty();
}

std::vector<std::string> VariantMap::names() const
{
  std::vector<std::string> result;
  result.reserve(size());
  for (auto it = constBegin(), itEnd = constEnd(); it != itEnd; ++it)
    result.push_back((*it).first);
  return result;
}

void VariantMap::setValue(const std::string& name, const Variant& v)
{
  m_map[name] = v;
}

Variant VariantMap::value(const std::string& name) const
{
  auto iter = m_map.find(name);
  if (iter == m_map.end())
    return Variant();

  return iter->second;
}

bool VariantMap::hasValue(const std::string& name) const
{
  return m_map.find(name) != m_map.end();
}

VariantMap::iterator VariantMap::begin()
{
  return m_map.begin();
}

VariantMap::const_iterator VariantMap::begin() const
{
  return m_map.begin();
}

VariantMap::const_iterator VariantMap::constBegin() const
{
  return m_map.begin();
}

VariantMap::iterator VariantMap::end()
{
  return m_map.end();
}

VariantMap::const_iterator VariantMap::end() const
{
  return m_map.end();
}

VariantMap::const_iterator VariantMap::constEnd() const
{
  return m_map.end();
}

} // end Avogadro namespace

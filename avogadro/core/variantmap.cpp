/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2011-2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "variantmap.h"

namespace Avogadro {
namespace Core {

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
  for (const_iterator it = constBegin(), itEnd = constEnd(); it != itEnd; ++it)
    result.push_back((*it).first);
  return result;
}

void VariantMap::setValue(const std::string& name, const Variant& v)
{
  m_map[name] = v;
}

Variant VariantMap::value(const std::string& name) const
{
  std::map<std::string, Variant>::const_iterator iter = m_map.find(name);
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

} // end Core namespace
} // end Avogadro namespace

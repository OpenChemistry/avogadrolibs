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

// === VariantMap ========================================================== //
/// \class VariantMap
/// \brief The VariantMap class provides a map between string keys
///        and variant values.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a new variant map object.
VariantMap::VariantMap()
{
}

/// Destroys the variant map.
VariantMap::~VariantMap()
{
}

// --- Properties ---------------------------------------------------------- //
/// Returns the size of the variant map.
size_t VariantMap::size() const
{
  return m_map.size();
}

/// Returns \c true if the variant map is empty (i.e. size() ==
/// \c 0).
bool VariantMap::isEmpty() const
{
  return m_map.empty();
}

/// Returns the names of the entries in the map.
std::vector<std::string> VariantMap::names() const
{
  std::vector<std::string> result;
  result.reserve(size());
  for (const_iterator it = constBegin(), itEnd = constEnd(); it != itEnd; ++it)
    result.push_back((*it).first);
  return result;
}

// --- Values -------------------------------------------------------------- //
/// Sets the value of \p name to \p v.
void VariantMap::setValue(const std::string &name, const Variant &v)
{
  m_map[name] = v;
}

/// Returns the value for \p name. If \p name is not found a null
/// variant is returned.
Variant VariantMap::value(const std::string &name) const
{
  std::map<std::string, Variant>::const_iterator iter = m_map.find(name);
  if (iter == m_map.end())
    return Variant();

  return iter->second;
}

/// Return an iterator pointing to the beginning of the map.
VariantMap::iterator VariantMap::begin()
{
  return m_map.begin();
}

/// \overload
VariantMap::const_iterator VariantMap::begin() const
{
  return m_map.begin();
}

/// Return an const_iterator pointing to the beginning of the map.
VariantMap::const_iterator VariantMap::constBegin() const
{
  return m_map.begin();
}

/// Return an iterator pointing to the end of the map.
VariantMap::iterator VariantMap::end()
{
  return m_map.end();
}

/// \overload
VariantMap::const_iterator VariantMap::end() const
{
  return m_map.end();
}

/// Return an const_iterator pointing to the end of the map.
VariantMap::const_iterator VariantMap::constEnd() const
{
  return m_map.end();
}

} // end Core namespace
} // end Avogadro namespace

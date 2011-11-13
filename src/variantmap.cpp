/******************************************************************************

  This source file is part of the MolCore project.

  Copyright 2011 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "variantmap.h"

namespace MolCore {

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
  if(iter == m_map.end())
    return Variant();

  return iter->second;
}

} // end MolCore namespace

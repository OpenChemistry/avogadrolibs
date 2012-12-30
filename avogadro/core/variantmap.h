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

#ifndef AVOGADRO_CORE_VARIANTMAP_H
#define AVOGADRO_CORE_VARIANTMAP_H

#include "avogadrocore.h"

#include "variant.h"

#include <map>
#include <string>
#include <vector>

namespace Avogadro {
namespace Core {

/*!
 * \class VariantMap variantmap.h <avogadro/core/variantmap.h>
 * \brief The VariantMap class provides a map between string keys and variant
 * values.
 */

class AVOGADROCORE_EXPORT VariantMap
{
public:
  typedef std::map<std::string, Variant>::iterator iterator;
  typedef std::map<std::string, Variant>::const_iterator const_iterator;

  /*! Creates a new variant map object. */
  VariantMap();

  /*! Destroys the variant map. */
  ~VariantMap();

  /*! Returns the size of the variant map. */
  size_t size() const;

  /*! Returns \c true if the variant map is empty (i.e. size() == \c 0). */
  bool isEmpty() const;

  /*! Returns the names of the entries in the map. */
  std::vector<std::string> names() const;

  /*! Sets the value of \p name to \p v. */
  void setValue(const std::string &name, const Variant &v);

  /*!
   * Returns the value for \p name. If \p name is not found a null variant is
   * returned.
   */
  Variant value(const std::string &name) const;

  /*! Return an iterator pointing to the beginning of the map. */
  iterator begin();

  /*! \overload */
  const_iterator begin() const;

  /*! Return a const_iterator pointing to the beginning of the map. */
  const_iterator constBegin() const;

  /*! Return an iterator pointing to the end of the map. */
  iterator end();

  /*! \overload */
  const_iterator end() const;

  /*! Return a const_iterator pointing to the end of the map. */
  const_iterator constEnd() const;

private:
  std::map<std::string, Variant> m_map;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_VARIANTMAP_H

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

class AVOGADROCORE_EXPORT VariantMap
{
public:
  // typedefs
  typedef std::map<std::string, Variant>::iterator iterator;
  typedef std::map<std::string, Variant>::const_iterator const_iterator;

  // construction and destruction
  VariantMap();
  virtual ~VariantMap();

  // properties
  size_t size() const;
  bool isEmpty() const;
  std::vector<std::string> names() const;

  // values
  void setValue(const std::string &name, const Variant &v);
  Variant value(const std::string &name) const;

  // iterator access
  iterator begin();
  const_iterator begin() const;
  const_iterator constBegin() const;

  iterator end();
  const_iterator end() const;
  const_iterator constEnd() const;

private:
  std::map<std::string, Variant> m_map;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_VARIANTMAP_H

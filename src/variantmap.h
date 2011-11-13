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

#ifndef MOLCORE_VARIANTMAP_H
#define MOLCORE_VARIANTMAP_H

#include "molcore.h"

#include "variant.h"

#include <map>
#include <string>

namespace MolCore {

class MOLCORE_EXPORT VariantMap
{
public:
  // construction and destruction
  VariantMap();
  ~VariantMap();

  // properties
  size_t size() const;
  bool isEmpty() const;

  // values
  void setValue(const std::string &name, const Variant &v);
  Variant value(const std::string &name) const;

private:
  std::map<std::string, Variant> m_map;
};

} // end MolCore namespace

#endif // MOLCORE_VARIANTMAP_H

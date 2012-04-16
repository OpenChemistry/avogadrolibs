/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_ELEMENTS_H
#define AVOGADRO_CORE_ELEMENTS_H

#include "avogadrocore.h"

#include <string>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT Elements
{
public:
  Elements();
  ~Elements();

  static unsigned char atomicNumberFromSymbol(const std::string &symbol);
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ELEMENTS_H

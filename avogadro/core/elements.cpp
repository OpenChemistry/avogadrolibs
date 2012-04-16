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

#include "elements.h"

namespace Avogadro {
namespace Core {

Elements::Elements()
{
}

Elements::~Elements()
{
}

unsigned char Elements::atomicNumberFromSymbol(const std::string &symbol)
{
  if (symbol.length() == 1) {
    switch (symbol[0]) {
    case 'H':
      return 1;
    case 'B':
      return 5;
    case 'C':
      return 6;
    case 'N':
      return 7;
    case 'O':
      return 8;
    case 'F':
      return 9;
    case 'P':
      return 15;
    case 'S':
      return 16;
    case 'K':
      return 19;
    case 'V':
      return 23;
    case 'Y':
      return 39;
    case 'I':
      return 53;
    case 'W':
      return 74;
    case 'U':
      return 92;
    default:
      return 0;
    }
  }
  else {
    // FIXME: I need implementing!
    return 0;
  }
}

} // end Core namespace
} // end Avogadro namespace

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

#include "elementdata.h"

namespace Avogadro {
namespace Core {

Elements::Elements()
{
}

Elements::~Elements()
{
}

unsigned char Elements::elementCount()
{
  return element_count;
}

unsigned char Elements::atomicNumberFromName(const std::string &name)
{
  for (unsigned char i = 0; i < element_count; ++i)
    if (name == element_names[i])
      return i;
  return InvalidElement;
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
      return InvalidElement;
    }
  }
  else {
    for (unsigned char i = 0; i < element_count; ++i)
      if (symbol == element_symbols[i])
        return i;
    return InvalidElement;
  }
}

const char * Elements::name(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_names[atomicNumber];
  else
    return element_names[0];
}

const char * Elements::symbol(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_symbols[atomicNumber];
  else
    return element_symbols[0];
}

double Elements::mass(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_masses[atomicNumber];
  else
    return element_masses[0];
}

double Elements::radiusVDW(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_VDW[atomicNumber];
  else
    return element_VDW[0];
}

double Elements::radiusCovalent(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_covalent[atomicNumber];
  else
    return element_covalent[0];
}

const unsigned char * Elements::color(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_color[atomicNumber];
  else
    return element_color[0];
}

} // end Core namespace
} // end Avogadro namespace

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

#include "avogadrocore.h"
#include "elementdata.h"
#include "utilities.h"

#include <algorithm>
#include <cctype>
#include <vector>

using Avogadro::Core::isCustomElement;

namespace Avogadro {
namespace Core {

// Handle custom element identifiers:
namespace {
const static std::string CustomElementSymbolPrefix = "X";
const static std::string CustomElementNamePrefix = "CustomElement_";

static std::vector<std::string> CustomElementSymbols;
static std::vector<std::string> CustomElementNames;

// Match carbon's radii
static double CustomElementCovalentRadius = element_covalent[6];
static double CustomElementVDWRadius = element_VDW[6];

inline std::string encodeCustomElement(unsigned char atomicNumber)
{
  std::string result;
  if (isCustomElement(atomicNumber)) {
    result.resize(2);
    unsigned char index = atomicNumber - Avogadro::CustomElementMin;
    result[0] = 'a' + static_cast<char>(index / 26);
    result[1] = 'a' + static_cast<char>(index % 26);
  }
  return result;
}

inline unsigned char decodeCustomElement(const std::string& str)
{
  if (str.size() == 2) {
    if (str[0] >= 'a' && str[0] <= 'z' && str[1] >= 'a' && str[1] <= 'z') {
      return CustomElementMin + static_cast<unsigned char>(str[0] - 'a') * 26 +
             static_cast<unsigned char>(str[1] - 'a');
    }
  }
  return Avogadro::InvalidElement;
}

inline unsigned char interpretCustomElementName(const std::string& name)
{
  if (startsWith(name, CustomElementNamePrefix)) {
    const std::string number(name.substr(CustomElementNamePrefix.size()));
    return decodeCustomElement(number);
  }
  return InvalidElement;
}

inline std::string createCustomElementName(unsigned char atomicNumber)
{
  return CustomElementNamePrefix + encodeCustomElement(atomicNumber);
}

inline const char* customElementName(unsigned char atomicNumber)
{
  return CustomElementNames[atomicNumber - CustomElementMin].c_str();
}

inline unsigned char interpretCustomElementSymbol(const std::string& symbol)
{
  if (symbol.size() == 3)
    return decodeCustomElement(symbol.substr(1));
  return InvalidElement;
}

inline std::string createCustomElementSymbol(unsigned char atomicNumber)
{
  return CustomElementSymbolPrefix + encodeCustomElement(atomicNumber);
}

inline const char* customElementSymbol(unsigned char atomicNumber)
{
  return CustomElementSymbols[atomicNumber - CustomElementMin].c_str();
}

inline unsigned char* customElementColor(unsigned char atomicNumber)
{
  return Core::element_color[atomicNumber % element_count];
}

// Initialize the static lookup tables.
class InitializeCustomElementTables
{
public:
  InitializeCustomElementTables()
  {
    CustomElementSymbols.resize(CustomElementCount);
    CustomElementNames.resize(CustomElementCount);
    std::string suffix;
    for (unsigned char i = CustomElementMin; i <= CustomElementMax; ++i) {
      suffix = encodeCustomElement(i);
      CustomElementSymbols[i - CustomElementMin] =
        CustomElementSymbolPrefix + suffix;
      CustomElementNames[i - CustomElementMin] =
        CustomElementNamePrefix + suffix;
    }
  }
} CustomElementTableInitializer;

} // end anon namespace

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

unsigned char Elements::atomicNumberFromName(const std::string& name)
{
  for (unsigned char i = 0; i < element_count; ++i)
    if (name == element_names[i])
      return i;

  return interpretCustomElementName(name);
}

unsigned char Elements::atomicNumberFromSymbol(const std::string& symbol)
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
  } else {
    for (unsigned char i = 0; i < element_count; ++i)
      if (symbol == element_symbols[i])
        return i;
    return interpretCustomElementSymbol(symbol);
  }
}

unsigned char Elements::guessAtomicNumber(const std::string& inputStr)
{
  std::string str(trimmed(inputStr));
  if (str.empty())
    return InvalidElement;

  // atomic number?
  bool ok;
  int atomicNumberInt = lexicalCast<int>(str, ok);
  if (ok)
    return static_cast<unsigned char>(atomicNumberInt);

  // Format string as text
  std::transform(str.begin(), str.end(), str.begin(), tolower);
  str[0] = static_cast<char>(toupper(static_cast<int>(str[0])));

  int length = str.size();
  unsigned char atomicNumber;
  while (length > 0) {
    if (length > 3)
      atomicNumber = atomicNumberFromName(str.substr(0, length));
    else
      atomicNumber = atomicNumberFromSymbol(str.substr(0, length));
    if (atomicNumber != InvalidElement)
      break;
    length--;
  }

  return atomicNumber;
}

const char* Elements::name(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_names[atomicNumber];
  else if (isCustomElement(atomicNumber))
    return customElementName(atomicNumber);
  else
    return element_names[0];
}

const char* Elements::symbol(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_symbols[atomicNumber];
  else if (isCustomElement(atomicNumber))
    return customElementSymbol(atomicNumber);
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
  else if (isCustomElement(atomicNumber))
    return CustomElementVDWRadius;
  else
    return element_VDW[0];
}

double Elements::radiusCovalent(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_covalent[atomicNumber];
  else if (isCustomElement(atomicNumber))
    return CustomElementCovalentRadius;
  else
    return element_covalent[0];
}

const unsigned char* Elements::color(unsigned char atomicNumber)
{
  if (atomicNumber < element_count)
    return element_color[atomicNumber];
  else if (isCustomElement(atomicNumber))
    return customElementColor(atomicNumber);
  else
    return element_color[0];
}

} // end Core namespace
} // end Avogadro namespace

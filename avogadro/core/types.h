/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_CORE_TYPES_H
#define AVOGADRO_CORE_TYPES_H

#include "avogadrocoreexport.h"

namespace Avogadro {

/** Symbolic constants representing various built-in C++ types. */
enum Type {
  UnknownType = -1,
  CharType,
  UCharType,
  ShortType,
  UShortType,
  IntType,
  UIntType,
  FloatType,
  DoubleType
};

template <typename T>
class TypeTraits
{
public:
  enum { EnumValue = -1 };
};

template < >
class TypeTraits<char>
{
public:
  enum { EnumValue = CharType };
};

template < >
class TypeTraits<unsigned char>
{
public:
  enum { EnumValue = UCharType };
};

template < >
class TypeTraits<short>
{
public:
  enum { EnumValue = ShortType };
};

template < >
class TypeTraits<unsigned short>
{
public:
  enum { EnumValue = UShortType };
};

template < >
class TypeTraits<int>
{
public:
  enum { EnumValue = IntType };
};

template < >
class TypeTraits<unsigned int>
{
public:
  enum { EnumValue = UIntType };
};

template < >
class TypeTraits<float>
{
public:
  enum { EnumValue = FloatType };
};

template < >
class TypeTraits<double>
{
public:
  enum { EnumValue = DoubleType };
};

} // end Avogadro namespace

#endif // AVOGADRO_CORE_H

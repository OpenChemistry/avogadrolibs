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

#ifndef AVOGADRO_CORE_VARIANT_H
#define AVOGADRO_CORE_VARIANT_H

#include "avogadrocore.h"
#include "matrix.h"

#include <string>

namespace Avogadro {
namespace Core {

class AVOGADROCORE_EXPORT Variant
{
public:
  // enumerations
  enum Type {
    Null,
    Bool,
    Int,
    Long,
    Float,
    Double,
    Pointer,
    String,
    Matrix
  };

  // construction and destruction
  inline Variant();
  template<typename T> Variant(T value);
  inline Variant(const Variant &variant);
  inline ~Variant();

  // properties
  inline Type type() const;
  inline bool isNull() const;

  // value
  template<typename T> bool setValue(T value);
  template<typename T> T value() const;
  inline void clear();

  // conversions
  inline bool toBool() const;
  inline char toChar() const;
  inline unsigned char toUChar() const;
  inline short toShort() const;
  inline unsigned short toUShort() const;
  inline int toInt() const;
  inline unsigned int toUInt() const;
  inline long toLong() const;
  inline unsigned long toULong() const;
  inline float toFloat() const;
  inline double toDouble() const;
  inline Real toReal() const;
  inline void* toPointer() const;
  inline std::string toString() const;
  inline MatrixX toMatrix() const;
  inline const MatrixX& toMatrixRef() const;

  // operators
  inline Variant& operator=(const Variant &variant);

private:
  template<typename T> static T lexical_cast(const std::string &string);

private:
  Type m_type;
  union {
    bool _bool;
    char _char;
    int _int;
    long _long;
    float _float;
    double _double;
    void *pointer;
    std::string *string;
    MatrixX *matrix;
  } m_value;
};

} // end Core namespace
} // end Avogadro namespace

#include "variant-inline.h"

#endif // AVOGADRO_CORE_VARIANT_H

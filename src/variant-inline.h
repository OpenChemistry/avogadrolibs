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

#ifndef MOLCORE_VARIANT_INLINE_H
#define MOLCORE_VARIANT_INLINE_H

#include "variant.h"

#include <sstream>

namespace MolCore {

// === Variant ============================================================= //
/// \class Variant
/// \brief The Variant class represents a union of data values.
///
/// Variant objects allow for the storage of and conversion between
/// a variety of different data types.

// --- Construction and Destruction ---------------------------------------- //
/// Creates a null variant.
inline Variant::Variant()
  : m_type(Null)
{
}

/// Creates a variant to store \p value.
template<typename T>
inline Variant::Variant(T v)
  : m_type(Null)
{
  setValue(v);
}

/// Creates a new copy of \p variant.
inline Variant::Variant(const Variant &variant)
  : m_type(variant.type())
{
  if(m_type == String){
    m_value.string = new std::string(variant.toString());
  }
  else if(m_type != Null){
    m_value = variant.m_value;
  }
}

/// Destroys the variant object
inline Variant::~Variant()
{
  clear();
}

// --- Properties ---------------------------------------------------------- //
/// Returns variant's type.
inline Variant::Type Variant::type() const
{
  return m_type;
}

/// Returns \c true if the variant is null.
inline bool Variant::isNull() const
{
  return m_type == Null;
}

// --- Value --------------------------------------------------------------- //
/// Sets the value of the variant to \p value.
template<typename T>
inline bool Variant::setValue(T v)
{
  CHEMKIT_UNUSED(v);

  clear();

  return false;
}

template<>
inline bool Variant::setValue(bool v)
{
  clear();

  m_type = Bool;
  m_value._bool = v;

  return true;
}

template<>
inline bool Variant::setValue(char v)
{
  clear();

  m_type = Int;
  m_value._int = v;

  return true;
}

template<>
inline bool Variant::setValue(short v)
{
  clear();

  m_type = Int;
  m_value._int = v;

  return true;
}

template<>
inline bool Variant::setValue(int v)
{
  clear();

  m_type = Int;
  m_value._int = v;

  return true;
}

template<>
inline bool Variant::setValue(long v)
{
  clear();

  m_type = Long;
  m_value._long = v;

  return true;
}

template<>
inline bool Variant::setValue(float v)
{
  clear();

  m_type = Float;
  m_value._float = v;

  return true;
}

template<>
inline bool Variant::setValue(double v)
{
  clear();

  m_type = Double;
  m_value._double = v;

  return true;
}

template<>
inline bool Variant::setValue(std::string string)
{
  clear();

  m_type = String;
  m_value.string = new std::string(string);

  return true;
}

template<>
inline bool Variant::setValue(const char *string)
{
  return setValue(std::string(string));
}

template<>
inline bool Variant::setValue(void *pointer)
{
  clear();

  m_type = Pointer;
  m_value.pointer = pointer;

  return true;
}

/// Returns the value of the variant in the type given by \c T.
template<typename T>
inline T Variant::value() const
{
  return 0;
}

template<>
inline bool Variant::value() const
{
  if(m_type == Bool){
    return m_value._bool;
  }
  else if(m_type == Int){
    return static_cast<bool>(m_value._int);
  }

  return false;
}

template<>
inline char Variant::value() const
{
  if(m_type == Int){
    return static_cast<char>(m_value._int);
  }
  else if(m_type == String && !m_value.string->empty()){
    return m_value.string->at(0);
  }

  return '\0';
}

template<>
inline short Variant::value() const
{
  if(m_type == Int){
    return static_cast<short>(m_value._int);
  }
  else if(m_type == String){
    return lexical_cast<short>(*m_value.string);
  }

  return 0;
}

template<>
inline int Variant::value() const
{
  if(m_type == Int){
    return m_value._int;
  }
  else if(m_type == Bool){
    return static_cast<int>(m_value._bool);
  }
  else if(m_type == Float){
    return static_cast<int>(m_value._float);
  }
  else if(m_type == Double){
    return static_cast<int>(m_value._double);
  }
  else if(m_type == String){
    return lexical_cast<int>(*m_value.string);
  }

  return 0;
}

template<>
inline long Variant::value() const
{
  if(m_type == Long){
    return m_value._long;
  }
  else if(m_type == Int){
    return static_cast<long>(m_value._int);
  }
  else if(m_type == String){
    return lexical_cast<long>(*m_value.string);
  }

  return 0;
}

template<>
inline float Variant::value() const
{
  if(m_type == Float){
    return m_value._float;
  }
  else if(m_type == Double){
    return static_cast<float>(m_value._double);
  }
  else if(m_type == Int){
    return static_cast<float>(m_value._int);
  }
  else if(m_type == String){
    return lexical_cast<float>(*m_value.string);
  }

  return 0;
}

template<>
inline double Variant::value() const
{
  if(m_type == Double){
    return m_value._double;
  }
  else if(m_type == Float){
    return static_cast<double>(m_value._float);
  }
  else if(m_type == Int){
    return static_cast<double>(m_value._int);
  }
  else if(m_type == String){
    return lexical_cast<double>(*m_value.string);
  }

  return 0;
}

template<>
inline void* Variant::value() const
{
  if(m_type == Pointer){
    return m_value.pointer;
  }

  return 0;
}

template<>
inline std::string Variant::value() const
{
  if(m_type == String){
    return *m_value.string;
  }

  std::stringstream string;

  if(m_type == Int){
    string << m_value._int;
  }
  else if(m_type == Float){
    string << m_value._float;
  }
  else if(m_type == Double){
    string << m_value._double;
  }

  return string.str();
}

/// Clears the variant's data and sets the variant to null.
inline void Variant::clear()
{
  if(m_type == String){
    delete m_value.string;
    m_value.string = 0;
  }

  m_type = Null;
}

// --- Conversions --------------------------------------------------------- //
/// Returns the value of the variant as a \c bool.
inline bool Variant::toBool() const
{
  return value<bool>();
}

/// Returns the value of the variant as a \c char.
inline char Variant::toChar() const
{
  return value<char>();
}

/// Returns the value of the variant as an \c unsigned \c char.
inline unsigned char Variant::toUChar() const
{
  return value<unsigned char>();
}

/// Returns the value of the variant as a \c short.
inline short Variant::toShort() const
{
  return value<short>();
}

/// Returns the value of the variant as an \c unsigned \c short.
inline unsigned short Variant::toUShort() const
{
  return value<unsigned short>();
}

/// Returns the value of the variant as an \c int.
inline int Variant::toInt() const
{
  return value<int>();
}

/// Returns the value of the variant as an \c unsigned \c int.
inline unsigned int Variant::toUInt() const
{
  return value<unsigned int>();
}

/// Returns the value of the variant as a \c long.
inline long Variant::toLong() const
{
  return value<long>();
}

/// Returns the value of the variant as an \c unsigned \c long.
inline unsigned long Variant::toULong() const
{
  return value<unsigned long>();
}

/// Returns the value of the variant as a \c float.
inline float Variant::toFloat() const
{
  return value<float>();
}

/// Returns the value of the variant as a \c double.
inline double Variant::toDouble() const
{
  return value<double>();
}

/// Returns the value of the variant as a \c Real.
inline Real Variant::toReal() const
{
  return value<Real>();
}

/// Returns the value of the variant as a pointer.
inline void* Variant::toPointer() const
{
  return value<void *>();
}

/// Returns the value of the variant as a string.
inline std::string Variant::toString() const
{
  return value<std::string>();
}

// --- Operators ----------------------------------------------------------- //
inline Variant& Variant::operator=(const Variant &variant)
{
  if(this != &variant){
    // clear previous data
    clear();

    // set new type
    m_type = variant.m_type;

    // set new value
    if(m_type == String){
      m_value.string = new std::string(variant.toString());
    }
    else if(m_type != Null){
      m_value = variant.m_value;
    }
  }

  return *this;
}

// --- Internal Methods ---------------------------------------------------- //
template<typename T>
inline T Variant::lexical_cast(const std::string &string)
{
  T value;
  std::istringstream(string) >> value;
  return value;
}

} // end MolCore namespace

#endif // MOLCORE_VARIANT_INLINE_H

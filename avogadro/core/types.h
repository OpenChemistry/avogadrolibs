/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_TYPES_H
#define AVOGADRO_CORE_TYPES_H

namespace Avogadro {

/** Symbolic constants representing various built-in C++ types. */
enum Type
{
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
  enum
  {
    EnumValue = -1
  };
  static const char* name() { return "Unsupported type."; }
};

template <>
class TypeTraits<char>
{
public:
  enum
  {
    EnumValue = CharType
  };
  static const char* name() { return "char"; }
};

template <>
class TypeTraits<unsigned char>
{
public:
  enum
  {
    EnumValue = UCharType
  };
  static const char* name() { return "unsigned char"; }
};

template <>
class TypeTraits<short>
{
public:
  enum
  {
    EnumValue = ShortType
  };
  static const char* name() { return "short"; }
};

template <>
class TypeTraits<unsigned short>
{
public:
  enum
  {
    EnumValue = UShortType
  };
  static const char* name() { return "unsigned short"; }
};

template <>
class TypeTraits<int>
{
public:
  enum
  {
    EnumValue = IntType
  };
  static const char* name() { return "int"; }
};

template <>
class TypeTraits<unsigned int>
{
public:
  enum
  {
    EnumValue = UIntType
  };
  static const char* name() { return "unsigned int"; }
};

template <>
class TypeTraits<float>
{
public:
  enum
  {
    EnumValue = FloatType
  };
  static const char* name() { return "float"; }
};

template <>
class TypeTraits<double>
{
public:
  enum
  {
    EnumValue = DoubleType
  };
  static const char* name() { return "double"; }
};

} // end Avogadro namespace

#endif // AVOGADRO_CORE_H

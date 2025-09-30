/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_VARIANT_INLINE_H
#define AVOGADRO_CORE_VARIANT_INLINE_H

#include "variant.h"

#include <iostream>
#include <sstream>

namespace Avogadro::Core {

inline Variant::Variant() : m_type(Null) {}

inline Variant::Variant(double x, double y, double z) : m_type(Vector)
{
  Vector3* v = new Vector3(x, y, z);
  m_value.vector = v;
}

template <typename T>
inline Variant::Variant(T v) : m_type(Null)
{
  setValue(v);
}

template <>
inline Variant::Variant(char v) : m_type(Int)
{
  m_value._int = static_cast<unsigned char>(v);
}

template <>
inline Variant::Variant(const char* v) : m_type(String)
{
  m_value.string = new std::string(v);
}

template <>
inline Variant::Variant(const MatrixXf& v) : m_type(Matrix)
{
  MatrixX* m = new MatrixX(v.rows(), v.cols());
  *m = v.cast<double>();
  m_value.matrix = m;
}

template <>
inline Variant::Variant(const Vector3& v) : m_type(Vector)
{
  Vector3* _v = new Vector3(v);
  m_value.vector = _v;
}

template <>
inline Variant::Variant(const Vector3f& v) : m_type(Vector)
{
  Vector3* _v = new Vector3(v.x(), v.y(), v.z());
  m_value.vector = _v;
}

template <>
inline Variant::Variant(const std::vector<double>& v) : m_type(Matrix)
{
  MatrixX* m = new MatrixX(v.size(), 1);
  for (size_t i = 0; i < v.size(); ++i)
    m->coeffRef(i, 0) = v[i];
  m_value.matrix = m;
}

inline Variant::Variant(const Variant& variant) : m_type(variant.type())
{
  if (m_type == String)
    m_value.string = new std::string(variant.toString());
  else if (m_type == Matrix)
    m_value.matrix = new MatrixX(*variant.m_value.matrix);
  else if (m_type == Vector)
    m_value.vector = new Vector3(*variant.m_value.vector);
  else if (m_type != Null)
    m_value = variant.m_value;
}

inline Variant::~Variant()
{
  clear();
}

inline Variant::Type Variant::type() const
{
  return m_type;
}

inline bool Variant::isNull() const
{
  return m_type == Null;
}

inline bool Variant::setValue(double x, double y, double z)
{
  clear();

  m_type = Vector;
  m_value.vector = new Vector3(x, y, z);

  return true;
}

inline bool Variant::setValue(const std::vector<double>& v)
{
  clear();

  m_type = Matrix;
  m_value.matrix = new MatrixX(v.size(), 1);
  for (size_t i = 0; i < v.size(); ++i)
    m_value.matrix->coeffRef(i, 0) = v[i];

  return true;
}

template <typename T>
inline bool Variant::setValue(T v)
{
  AVO_UNUSED(v);

#ifndef NDEBUG
#if defined(_MSC_VER)
  std::cerr << " Variant::setValue() not implemented for " << __FUNCSIG__
            << std::endl;
#else
  std::cerr << " Variant::setValue() not implemented for "
            << __PRETTY_FUNCTION__ << std::endl;
#endif
#endif

  clear();

  return false;
}

template <>
inline bool Variant::setValue(bool v)
{
  clear();

  m_type = Bool;
  m_value._bool = v;

  return true;
}

template <>
inline bool Variant::setValue(char v)
{
  clear();

  m_type = Int;
  m_value._int = static_cast<unsigned char>(v);

  return true;
}

template <>
inline bool Variant::setValue(short v)
{
  clear();

  m_type = Int;
  m_value._int = v;

  return true;
}

template <>
inline bool Variant::setValue(int v)
{
  clear();

  m_type = Int;
  m_value._int = v;

  return true;
}

template <>
inline bool Variant::setValue(long v)
{
  clear();

  m_type = Long;
  m_value._long = v;

  return true;
}

template <>
inline bool Variant::setValue(float v)
{
  clear();

  m_type = Float;
  m_value._float = v;

  return true;
}

template <>
inline bool Variant::setValue(double v)
{
  clear();

  m_type = Double;
  m_value._double = v;

  return true;
}

template <>
inline bool Variant::setValue(std::string string)
{
  clear();

  m_type = String;
  m_value.string = new std::string(string);

  return true;
}

template <>
inline bool Variant::setValue(const char* string)
{
  return setValue(std::string(string));
}

template <>
inline bool Variant::setValue(void* pointer)
{
  clear();

  m_type = Pointer;
  m_value.pointer = pointer;

  return true;
}

template <>
inline bool Variant::setValue(MatrixX matrix)
{
  clear();

  m_type = Matrix;
  m_value.matrix = new MatrixX(matrix);

  return true;
}

template <>
inline bool Variant::setValue(Vector3 vector)
{
  clear();

  m_type = Vector;
  m_value.vector = new Vector3(vector);

  return true;
}

template <>
inline bool Variant::setValue(Vector3f vector)
{
  clear();

  m_type = Vector;
  m_value.vector = new Vector3(vector.x(), vector.y(), vector.z());

  return true;
}

template <typename T>
inline T Variant::value() const
{
  return 0;
}

template <>
inline bool Variant::value() const
{
  if (m_type == Bool)
    return m_value._bool;
  else if (m_type == Int)
    return m_value._int != 0;

  return false;
}

template <>
inline char Variant::value() const
{
  if (m_type == Int)
    return static_cast<char>(m_value._int);
  else if (m_type == String && !m_value.string->empty())
    return m_value.string->at(0);

  return '\0';
}

template <>
inline short Variant::value() const
{
  if (m_type == Int)
    return static_cast<short>(m_value._int);
  else if (m_type == String)
    return lexical_cast<short>(*m_value.string);

  return 0;
}

template <>
inline int Variant::value() const
{
  if (m_type == Int)
    return m_value._int;
  else if (m_type == Bool)
    return static_cast<int>(m_value._bool);
  else if (m_type == Float)
    return static_cast<int>(m_value._float);
  else if (m_type == Double)
    return static_cast<int>(m_value._double);
  else if (m_type == String)
    return lexical_cast<int>(*m_value.string);

  return 0;
}

template <>
inline long Variant::value() const
{
  if (m_type == Long)
    return m_value._long;
  else if (m_type == Int)
    return static_cast<long>(m_value._int);
  else if (m_type == String)
    return lexical_cast<long>(*m_value.string);

  return 0;
}

template <>
inline float Variant::value() const
{
  if (m_type == Float)
    return m_value._float;
  else if (m_type == Double)
    return static_cast<float>(m_value._double);
  else if (m_type == Int)
    return static_cast<float>(m_value._int);
  else if (m_type == String)
    return lexical_cast<float>(*m_value.string);

  return 0;
}

template <>
inline double Variant::value() const
{
  if (m_type == Double)
    return m_value._double;
  else if (m_type == Float)
    return static_cast<double>(m_value._float);
  else if (m_type == Int)
    return static_cast<double>(m_value._int);
  else if (m_type == String)
    return lexical_cast<double>(*m_value.string);

  return 0;
}

template <>
inline void* Variant::value() const
{
  if (m_type == Pointer)
    return m_value.pointer;

  return 0;
}

template <>
inline std::string Variant::value() const
{
  if (m_type == String)
    return *m_value.string;

  std::stringstream string;

  if (m_type == Int)
    string << m_value._int;
  else if (m_type == Float)
    string << m_value._float;
  else if (m_type == Double)
    string << m_value._double;

  return string.str();
}

template <>
inline MatrixX Variant::value() const
{
  if (m_type == Matrix)
    return *m_value.matrix;

  return MatrixX();
}

template <>
inline const MatrixX& Variant::value() const
{
  if (m_type == Matrix)
    return *m_value.matrix;

  // Use a static null matrix for the reference.
  static MatrixX nullMatrix(0, 0);
  return nullMatrix;
}

template <>
inline Vector3 Variant::value() const
{
  if (m_type == Vector)
    return *m_value.vector;

  return Vector3();
}

template <>
inline const Vector3& Variant::value() const
{
  if (m_type == Vector)
    return *m_value.vector;

  static Vector3 nullVector(0, 0, 0);
  return nullVector;
}

template <>
inline std::vector<double> Variant::value() const
{
  if (m_type == Matrix && m_value.matrix->cols() == 1) {
    std::vector<double> list(m_value.matrix->rows());
    for (int i = 0; i < m_value.matrix->rows(); ++i)
      list[i] = m_value.matrix->coeff(i, 0);
    return list;
  }

  return std::vector<double>();
}

inline void Variant::clear()
{
  if (m_type == String) {
    delete m_value.string;
    m_value.string = 0;
  } else if (m_type == Matrix) {
    delete m_value.matrix;
    m_value.matrix = 0;
  } else if (m_type == Vector) {
    delete m_value.vector;
    m_value.vector = 0;
  }

  m_type = Null;
}

inline bool Variant::toBool() const
{
  return value<bool>();
}

inline char Variant::toChar() const
{
  return value<char>();
}

inline unsigned char Variant::toUChar() const
{
  return value<unsigned char>();
}

inline short Variant::toShort() const
{
  return value<short>();
}

inline unsigned short Variant::toUShort() const
{
  return value<unsigned short>();
}

inline int Variant::toInt() const
{
  return value<int>();
}

inline unsigned int Variant::toUInt() const
{
  return value<unsigned int>();
}

inline long Variant::toLong() const
{
  return value<long>();
}

inline unsigned long Variant::toULong() const
{
  return value<unsigned long>();
}

inline float Variant::toFloat() const
{
  return value<float>();
}

inline double Variant::toDouble() const
{
  return value<double>();
}

inline Real Variant::toReal() const
{
  return value<Real>();
}

inline void* Variant::toPointer() const
{
  return value<void*>();
}

inline std::string Variant::toString() const
{
  return value<std::string>();
}

inline MatrixX Variant::toMatrix() const
{
  return value<MatrixX>();
}

inline const MatrixX& Variant::toMatrixRef() const
{
  return value<const MatrixX&>();
}

inline Vector3 Variant::toVector3() const
{
  return value<Vector3>();
}

inline std::vector<double> Variant::toList() const
{
  return value<std::vector<double>>();
}

// --- Operators ----------------------------------------------------------- //
inline Variant& Variant::operator=(const Variant& variant)
{
  if (this != &variant) {
    // Clear previous data,
    clear();

    // Set the new type.
    m_type = variant.m_type;

    // Set the new value,
    if (m_type == String)
      m_value.string = new std::string(variant.toString());
    else if (m_type == Matrix)
      m_value.matrix = new MatrixX(*variant.m_value.matrix);
    else if (m_type == Vector)
      m_value.vector = new Vector3(*variant.m_value.vector);
    else if (m_type != Null)
      m_value = variant.m_value;
  }

  return *this;
}

// --- Internal Methods ---------------------------------------------------- //
template <typename T>
inline T Variant::lexical_cast(const std::string& str)
{
  T value;
  std::istringstream(str) >> value;
  return value;
}

} // namespace Avogadro::Core

#endif // AVOGADRO_CORE_VARIANT_INLINE_H

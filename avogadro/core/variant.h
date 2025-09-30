/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_VARIANT_H
#define AVOGADRO_CORE_VARIANT_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"
#include "matrix.h"
#include "vector.h"

#include <string>

namespace Avogadro::Core {

/**
 * @class Variant variant.h <avogadro/core/variant.h>
 * @brief The Variant class represents a union of data values.
 *
 * Variant objects allow for the storage of and conversion between a variety of
 * different data types.
 */

class AVOGADROCORE_EXPORT Variant
{
public:
  // enumerations
  enum Type
  {
    Null,
    Bool,
    Int,
    Long,
    Float,
    Double,
    Pointer,
    String,
    Vector,
    Matrix
  };

  /** Creates a null variant. */
  inline Variant();

  /** Creates a variant to store @p value. */
  template <typename T>
  Variant(T value);

  /** Creates a new copy of @p variant. */
  inline Variant(const Variant& variant);

  /** Creates a variant to store a 3D vector */
  Variant(double x, double y, double z);

  /** Destroys the variant object. */
  inline ~Variant();

  /** @return variant's type. */
  inline Type type() const;

  /** @return \c true if the variant is null. */
  inline bool isNull() const;

  /** Sets the value of the variant to @p value. */
  template <typename T>
  bool setValue(T value);

  /** Sets the value of the variant to a 3D vector */
  bool setValue(double x, double y, double z);

  /** Sets the value of the variant to a vector<double> */
  bool setValue(const std::vector<double>& v);

  /** @return the value of the variant in the type given by \c T. */
  template <typename T>
  T value() const;

  /** Clears the variant's data and sets the variant to null. */
  inline void clear();

  /** @return the value of the variant as a \c bool. */
  inline bool toBool() const;

  /** @return the value of the variant as a \c char. */
  inline char toChar() const;

  /** @return the value of the variant as an \c unsigned \c char. */
  inline unsigned char toUChar() const;

  /** @return the value of the variant as a \c short. */
  inline short toShort() const;

  /** @return the value of the variant as an \c unsigned \c short. */
  inline unsigned short toUShort() const;

  /** @return the value of the variant as an \c int. */
  inline int toInt() const;

  /** @return the value of the variant as an \c unsigned \c int. */
  inline unsigned int toUInt() const;

  /**  @return the value of the variant as a \c long. */
  inline long toLong() const;

  /**  @return the value of the variant as an \c unsigned \c long. */
  inline unsigned long toULong() const;

  /** @return the value of the variant as a \c float. */
  inline float toFloat() const;

  /** @return the value of the variant as a \c double. */
  inline double toDouble() const;

  /** @return the value of the variant as a \c Real. */
  inline Real toReal() const;

  /** @return the value of the variant as a pointer. */
  inline void* toPointer() const;

  /** @return the value of the variant as a string. */
  inline std::string toString() const;

  /** @return the value of the variant as a MatrixX. */
  inline MatrixX toMatrix() const;

  /** @return the value of the variant as a Vector3 */
  inline Vector3 toVector3() const;

  /** @return the value as a vector<double> */
  inline std::vector<double> toList() const;

  /**
   * @return a reference to the value of the variant as a MatrixX.
   * This method will not perform any casting -- if type() is not exactly
   * MatrixX, the function will fail and return a reference to an empty MatrixX.
   */
  inline const MatrixX& toMatrixRef() const;

  // operators
  inline Variant& operator=(const Variant& variant);

private:
  template <typename T>
  static T lexical_cast(const std::string& string);

private:
  Type m_type;
  union
  {
    bool _bool;
    int _int;
    long _long;
    float _float;
    double _double;
    void* pointer;
    std::string* string;
    Vector3* vector;
    MatrixX* matrix;
  } m_value;
};

} // namespace Avogadro::Core

#include "variant-inline.h"

#endif // AVOGADRO_CORE_VARIANT_H

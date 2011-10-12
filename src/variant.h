#ifndef MOLCORE_VARIANT_H
#define MOLCORE_VARIANT_H

#include "molcore.h"

#include <string>

namespace MolCore {

class MOLCORE_EXPORT Variant
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
    String
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
  } m_value;
};

} // end MolCore namespace

#include "variant-inline.h"

#endif // MOLCORE_VARIANT_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_COORDINATESET_H
#define AVOGADRO_CORE_COORDINATESET_H

#include "avogadrocore.h"

#include <typeinfo>
#include <vector>

namespace Avogadro {
namespace Core {

/**
 * @class ArraySet coordinateset.h <avogadro/core/coordinateset.h>
 * @brief Base class for array type containers.
 *
 * This base class gives us the non-templated base class that stores all arrays
 * of data. You should use the base class as the container, and figure out its
 * type when using it.
 */
class ArraySet
{
public:
  ArraySet() : m_content(nullptr), m_data(nullptr) {}
  ~ArraySet() { delete m_content; }

  /** @return true if the type of the array matches the input type. */
  template <typename T>
  bool isType(const T&) const
  {
    return m_content ? typeid(T) == m_content->type() : false;
  }
  /*
    template<typename T>
    std::vector<T> data()
    {
      if (m_data && isType(T))
        return static_cast<std::vector<T> &>(*m_data);
      else
        return std::vector<T>();
    }
  */
protected:
  class PlaceHolder
  {
  public:
    virtual ~PlaceHolder() {}

    virtual const std::type_info& type() const = 0;

    virtual PlaceHolder* clone() const = 0;
  };

  template <typename ValueType>
  class Holder : public PlaceHolder
  {
  public:
    Holder(const ValueType& value) : m_content(value) {}

    const std::type_info& type() const { return typeid(ValueType); }

    PlaceHolder* clone() const { return new Holder(m_content); }

    ValueType m_content;
  };

  PlaceHolder* m_content;
  void* m_data;
};

/**
 * @class CoordinateSet coordinateset.h <avogadro/core/coordinateset.h>
 * @brief Templated class for array type containers.
 *
 * This class gives us the derived templated class that stores arrays of data.
 * of data. This class should be used to store concrete arrays, and can be
 * cast to ArraySet when stored in generic containers.
 */
template <typename T>
class CoordinateSet : public ArraySet
{
public:
  CoordinateSet() { m_content = new Holder<T>(T()); }

  ~CoordinateSet() {}

  // Properties
  void resize(Index _size) { m_coordinates.resize(_size); }
  Index size() const { return m_coordinates.size(); }
  std::vector<T>& coordinates() { return m_coordinates; }
  const std::vector<T>& coordinates() const { return m_coordinates; }

  // Inline operator methods.
  /** Returns the element at \index _index. */
  T operator()(Index _index) const { return m_coordinates.at(_index); }
  T& operator[](Index _index) { return m_coordinates[_index]; }
  const T& operator[](Index _index) const { return m_coordinates[_index]; }

private:
  std::vector<T> m_coordinates;
};

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_COORDINATESET_H

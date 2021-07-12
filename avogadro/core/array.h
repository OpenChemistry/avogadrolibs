/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_ARRAY_H
#define AVOGADRO_CORE_ARRAY_H

#include "avogadrocore.h"

#include <algorithm>
#include <vector>

namespace Avogadro {
namespace Core {

using std::size_t;

namespace internal {

template <typename T>
class ArrayRefContainer
{
public:
  typedef T ValueType;
  typedef std::vector<T> Parent; // The parent container for iterators etc

  // STL compatibility, forward typedefs from std::vector:
  typedef typename Parent::value_type value_type;
  typedef typename Parent::allocator_type allocator_type;
  typedef typename Parent::reference reference;
  typedef typename Parent::const_reference const_reference;
  typedef typename Parent::pointer pointer;
  typedef typename Parent::const_pointer const_pointer;
  typedef typename Parent::iterator iterator;
  typedef typename Parent::const_iterator const_iterator;
  typedef typename Parent::reverse_iterator reverse_iterator;
  typedef typename Parent::const_reverse_iterator const_reverse_iterator;
  typedef typename Parent::difference_type difference_type;
  typedef typename Parent::size_type size_type;

  ArrayRefContainer() : m_ref(1), data() {}

  explicit ArrayRefContainer(const size_t n,
                             const ValueType& value = ValueType())
    : m_ref(1), data(n, value)
  {}

  ArrayRefContainer(const ArrayRefContainer& other) : m_ref(1), data(other.data)
  {}

  template <typename InputIterator>
  ArrayRefContainer(InputIterator first, InputIterator last)
    : m_ref(1), data(first, last)
  {}

  // Increment the reference count.
  void reref() { ++m_ref; }

  // Decrement the reference count, return true unless the reference count has
  // dropped to zero. When it returns false, this object should be deleted.
  bool deref()
  {
    if (m_ref)
      --m_ref;
    return m_ref > 0;
  }

  unsigned int ref() const { return m_ref; }

  // Reference count
  unsigned int m_ref;
  // Container for our data
  std::vector<T> data;
};

} // namespace internal

/**
 * @class Array array.h <avogadro/core/array.h>
 * @brief Base class for array containers.
 *
 * This templated class gives us a container with copy-on-write semantics,
 * allowing for functions to effectively share data without exposing access or
 * copying large amounts of data until the container is changed.
 *
 * All const functions can be called without copying any data, but a call to a
 * non-const function will trigger a detach call. This is a no-op when the
 * reference count is 1, and will perform a deep copy when the reference count
 * is greater than 1.
 */
template <typename T>
class Array
{
public:
  typedef internal::ArrayRefContainer<T> Container;

public:
  typedef T ValueType;

  /** Typedefs for STL compatibility @{ */
  typedef typename Container::value_type value_type;
  typedef typename Container::allocator_type allocator_type;
  typedef typename Container::reference reference;
  typedef typename Container::const_reference const_reference;
  typedef typename Container::pointer pointer;
  typedef typename Container::const_pointer const_pointer;
  typedef typename Container::iterator iterator;
  typedef typename Container::const_iterator const_iterator;
  typedef typename Container::reverse_iterator reverse_iterator;
  typedef typename Container::const_reverse_iterator const_reverse_iterator;
  typedef typename Container::difference_type difference_type;
  typedef typename Container::size_type size_type;
  /** @} */

  /** Constructors for new containers. */
  Array() : d(new Container()) {}

  explicit Array(const size_t n, const ValueType& value = ValueType())
    : d(new Container(n, value))
  {}

  template <typename InputIterator>
  Array(InputIterator first, InputIterator last) : d(new Container(first, last))
  {}

  /** Copy constructor, note the copy made of the internal data of other. */
  Array(const Array& other)
  {
    other.d->reref();
    d = other.d;
  }

  ~Array();

  /**
   * Explicitly detach from any other implicitly shared containers. This is not
   * normally necessary, but can be useful when you want to ensure you have a
   * copy of all data.
   */
  void detachWithCopy();

  /**
   * Explicitly detach from any other implicitly shared containers. This
   * version does not copy the data.
   */
  void detach();

  /** Retrieve a pointer to the underlying data. */
  T* data()
  {
    detachWithCopy();
    return d->data.data();
  }

  const T* data() const { return d->data.data(); }

  const T* constData() const { return d->data.data(); }

  size_t size() const { return d->data.size(); }

  size_t max_size() const { return d->data.max_size(); }

  bool empty() const { return d->data.empty(); }

  size_t capacity() const { return d->data.capacity(); }

  void reserve(const size_t& sz)
  {
    detachWithCopy();
    d->data.reserve(sz);
  }

  void resize(const size_t& sz, const ValueType& t = ValueType())
  {
    detachWithCopy();
    d->data.resize(sz, t);
  }

  void clear()
  {
    detach();
    d->data.clear();
  }

  const_iterator begin() const { return d->data.begin(); }

  const_iterator end() const { return d->data.end(); }

  iterator begin()
  {
    detachWithCopy();
    return d->data.begin();
  }

  iterator end()
  {
    detachWithCopy();
    return d->data.end();
  }

  const_reverse_iterator rbegin() const { return d->data.rbegin(); }

  const_reverse_iterator rend() const { return d->data.rend(); }

  reverse_iterator rbegin()
  {
    detachWithCopy();
    return d->data.rbegin();
  }

  reverse_iterator rend()
  {
    detachWithCopy();
    return d->data.rend();
  }

  reference front()
  {
    detachWithCopy();
    return d->data.front();
  }

  const_reference front() const { return d->data.front(); }

  reference back()
  {
    detachWithCopy();
    return d->data.back();
  }

  const_reference back() const { return d->data.back(); }

  template <class InputIterator>
  void assign(InputIterator first, InputIterator last)
  {
    detachWithCopy();
    d->data.assign(first, last);
  }

  void assign(size_type n, const value_type& val)
  {
    detachWithCopy();
    d->data.assign(n, val);
  }

  void push_back(const ValueType& v)
  {
    detachWithCopy();
    d->data.push_back(v);
  }

  void pop_back()
  {
    detachWithCopy();
    d->data.pop_back();
  }

  iterator insert(iterator position, const value_type& val)
  {
    detachWithCopy();
    return d->data.insert(position, val);
  }

  void insert(iterator position, size_type n, const value_type& val)
  {
    detachWithCopy();
    d->data.insert(position, n, val);
  }

  template <class InputIterator>
  void insert(iterator position, InputIterator first, InputIterator last)
  {
    detachWithCopy();
    d->data.insert(position, first, last);
  }

  iterator erase(iterator position)
  {
    detachWithCopy();
    return d->data.erase(position);
  }

  iterator erase(iterator first, iterator last)
  {
    detachWithCopy();
    return d->data.erase(first, last);
  }

  const ValueType& operator[](const std::size_t& idx) const
  {
    return d->data[idx];
  }

  ValueType& operator[](const std::size_t& idx)
  {
    detachWithCopy();
    return d->data[idx];
  }

  ValueType at(const std::size_t& idx) const { return d->data.at(idx); }

  template <typename OtherT>
  Array& operator=(const std::vector<OtherT>& v)
  {
    detach();
    d->data = v;
    return *this;
  }

  template <typename OtherT>
  Array& operator=(const Array<OtherT>& v)
  {
    detach();
    d->data = v.d->data;
    return *this;
  }

  Array& operator=(const Array& v)
  {
    if (this != &v) {
      detach();
      d->data = v.d->data;
    }
    return *this;
  }

  void swap(Array<ValueType>& other)
  {
    using std::swap;
    swap(d, other.d);
  }

  /**
   * @param index array position to delete
   * if the index is valid swap it with the last position and pop back.
   * This function does not preserve the elements order.
   */
  void swapAndPop(Index index)
  {
    if (index >= d->data.size()) {
      return;
    }
    if (index != d->data.size() - 1) {
      d->data[index] = d->data.back();
    }
    d->data.pop_back();
  }

protected:
  Container* d;
};

template <typename T>
inline Array<T>::~Array()
{
  if (d && !d->deref())
    delete d;
}

template <typename T>
inline void Array<T>::detachWithCopy()
{
  if (d && d->ref() != 1) {
    Container* o = new Container(*d);
    d->deref();
    d = o;
  }
}

template <typename T>
inline void Array<T>::detach()
{
  if (d && d->ref() != 1) {
    d->deref();
    d = new Container;
  }
}

template <typename T>
inline bool operator==(const Array<T>& lhs, const Array<T>& rhs)
{
  return lhs.size() == rhs.size() &&
         std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

template <typename T>
inline bool operator!=(const Array<T>& lhs, const Array<T>& rhs)
{
  return !(lhs == rhs);
}

template <typename T>
inline bool operator<(const Array<T>& lhs, const Array<T>& rhs)
{
  return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(),
                                      rhs.end());
}

template <typename T>
inline bool operator>(const Array<T>& lhs, const Array<T>& rhs)
{
  return rhs < lhs;
}

template <typename T>
inline bool operator<=(const Array<T>& lhs, const Array<T>& rhs)
{
  return !(rhs < lhs);
}

template <typename T>
inline bool operator>=(const Array<T>& lhs, const Array<T>& rhs)
{
  return !(lhs < rhs);
}

template <typename T>
inline void swap(Array<T>& lhs, Array<T>& rhs)
{
  lhs.swap(rhs);
}

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_ARRAY_H

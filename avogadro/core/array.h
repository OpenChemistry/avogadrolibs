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

#ifndef AVOGADRO_CORE_ARRAY_H
#define AVOGADRO_CORE_ARRAY_H

#include "avogadrocore.h"

#include <vector>

namespace Avogadro {
namespace Core {

using std::size_t;

namespace internal {

template<typename T>
class ArrayRefContainer
{
public:
  typedef T ValueType;
  typedef std::vector<T> Parent; // The parent container for iterators etc
  typedef typename Parent::iterator iterator;
  typedef typename Parent::const_iterator const_iterator;

  ArrayRefContainer() : m_ref(1), data()
  {
  }

  explicit ArrayRefContainer(const size_t n, const ValueType &value = ValueType())
    : m_ref(1), data(n, value)
  {
  }

  ArrayRefContainer(const ArrayRefContainer &other)
    : m_ref(1), data(other.data)
  {
  }

  template<typename InputIterator>
  ArrayRefContainer(InputIterator first, InputIterator last)
    : m_ref(1), data(first, last)
  {
  }

  // Increment the reference count.
  void reref()
  {
    ++m_ref;
  }

  // Decrement the reference count, return true unless the reference count has
  // dropped to zero. When it returns false, this object should be deleted.
  bool deref()
  {
    if (m_ref)
      --m_ref;
    return m_ref > 0;
  }

  unsigned int ref() const
  {
    return m_ref;
  }

  // Reference count
  unsigned int m_ref;
  // Container for our data
  std::vector<T> data;
};

} // End internal namespace

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
template<typename T>
class Array
{
public:
  typedef internal::ArrayRefContainer<T> Container;

public:
  typedef T ValueType;

  typedef typename Container::iterator iterator;
  typedef typename Container::const_iterator const_iterator;

  /** Constructors for new containers. */
  Array() : d(new Container())
  {
  }

  explicit Array(const size_t n, const ValueType &value = ValueType())
    : d(new Container(n, value))
  {
  }

  template<typename InputIterator>
  Array(InputIterator first, InputIterator last)
    : d(new Container(first, last))
  {
  }

  /** Copy constructor, note the copy made of the internal data of other. */
  Array(const Array &other)
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
  void detach();

  /** Retrieve a pointer to the underlying data. */
  T* data()
  {
    detach();
    return &d->data[0];
  }

  const T* data() const
  {
    return &d->data[0];
  }

  const T* constData() const
  {
    return &d->data[0];
  }

  size_t size() const
  {
    return d->data.size();
  }

  bool empty() const
  {
    return d->data.empty();
  }

  size_t capacity() const
  {
    return d->data.capacity();
  }

  void reserve(const size_t& sz)
  {
    detach();
    d->data.reserve(sz);
  }

  void resize(const size_t& sz, ValueType t = ValueType())
  {
    detach();
    d->data.resize(sz,t);
  }

  void clear()
  {
    detach();
    d->data.clear();
  }

  const_iterator begin() const
  {
    return d->data.begin();
  }

  const_iterator end() const
  {
    return d->data.end();
  }

  iterator begin()
  {
    detach();
    return d->data.begin();
  }

  iterator end()
  {
    detach();
    return d->data.end();
  }

  void push_back(const ValueType& v)
  {
    detach();
    d->data.push_back(v);
  }

  const ValueType& operator [](const std::size_t& idx) const
  {
    return d->data[idx];
  }

  ValueType& operator [](const std::size_t& idx)
  {
    detach();
    return d->data[idx];
  }

  ValueType at(const std::size_t& idx) const
  {
    return d->data.at(idx);
  }

  template<typename OtherT>
  Array &operator=(const std::vector<OtherT> &v)
  {
    detach();
    d->data = v;
    return *this;
  }

  template<typename OtherT>
  Array &operator=(const Array<OtherT> &v)
  {
    detach();
    d->data = v.d->data;
    return *this;
  }

  Array &operator=(const Array &v)
  {
    detach();
    d->data = v.d->data;
    return *this;
  }

protected:
  Container *d;
};

template<typename T>
inline Array<T>::~Array()
{
  if (d && !d->deref())
    delete d;
}

template<typename T>
inline void Array<T>::detach()
{
  if (d && d->ref() != 1) {
    Container *o = new Container(*d);
    d->deref();
    d = o;
  }
}

} // end Core namespace
} // end Avogadro namespace

#endif // AVOGADRO_CORE_ARRAY_H

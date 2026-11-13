// Copyright 2019 Global Phasing Ltd.
//
// Span - span of array or std::vector.
// MutableVectorSpan - span of std::vector with insert() and erase()

#ifndef GEMMI_SPAN_HPP_
#define GEMMI_SPAN_HPP_

#include <algorithm>    // for find_if, find_if_not
#include <vector>
#include <stdexcept>    // for out_of_range
#include <type_traits>  // for remove_cv, conditional, is_const

namespace gemmi {

template<typename Item> struct MutableVectorSpan;

/// @brief Minimalistic span of array or vector, similar to C++20 std::span.
template<typename Item> struct Span {
  using iterator = Item*;
  using const_iterator = Item const*;
  using element_type = Item;
  using value_type = typename std::remove_cv<Item>::type;

  friend Span<const value_type>;
  friend MutableVectorSpan<value_type>;

  /// @brief Default constructor (empty span).
  Span() = default;
  /// @brief Construct span from pointer and size.
  /// @param begin pointer to first element
  /// @param n number of elements
  Span(iterator begin, std::size_t n) : begin_(begin), size_(n) {}

#if !defined(_MSC_VER) || _MSC_VER-0 >= 1926
  /// @brief Copy-convert constructor from mutable span to const span.
  template<typename T=Item>
  Span(const Span<value_type>& o,
       typename std::enable_if<std::is_const<T>::value>::type* = 0)
#else
  /// @brief Copy-convert constructor from mutable span to const span.
  Span(const Span<value_type>& o)
#endif
    : begin_(o.begin_), size_(o.size_) {}

  /// @brief Set the begin pointer.
  /// @param begin new begin pointer
  void set_begin(iterator begin) { begin_ = begin; }
  /// @brief Set the span size.
  /// @param n new size
  void set_size(std::size_t n) { size_ = n; }
  /// @brief Get const iterator to beginning.
  const_iterator begin() const { return begin_; }
  /// @brief Get const iterator to end.
  const_iterator end() const { return begin_ + size_; }
  /// @brief Get mutable iterator to beginning.
  iterator begin() { return begin_; }
  /// @brief Get mutable iterator to end.
  iterator end() { return begin_ + size_; }

  /// @brief Access first element.
  Item& front() { return *begin_; }
  /// @brief Access first element (const).
  const Item& front() const { return *begin_; }
  /// @brief Access last element.
  Item& back() { return *(begin_ + size_ - 1); }
  /// @brief Access last element (const).
  const Item& back() const { return *(begin_ + size_ - 1); }

  /// @brief Subscript access to element.
  const Item& operator[](std::size_t i) const { return *(begin_ + i); }
  /// @brief Subscript access to element (mutable).
  Item& operator[](std::size_t i) { return *(begin_ + i); }

  /// @brief Bounds-checked element access.
  /// @param i index
  /// @return reference to element at index i
  /// @throws std::out_of_range if index is out of bounds
  Item& at(std::size_t i) {
    if (i >= size())
      throw std::out_of_range("item index ouf of range: #" + std::to_string(i));
    return *(begin_ + i);
  }
  /// @brief Bounds-checked element access (const).
  /// @param i index
  /// @return const reference to element at index i
  /// @throws std::out_of_range if index is out of bounds
  const Item& at(std::size_t i) const {
    return const_cast<Span*>(this)->at(i);
  }

  /// @brief Get span size.
  std::size_t size() const { return size_; }
  /// @brief Check if span is empty.
  bool empty() const { return size_ == 0; }
  /// @brief Conversion to bool (true if not empty).
  explicit operator bool() const { return size_ != 0; }

  /// @brief Get a subspan from iterator range.
  /// @param first iterator to first element
  /// @param last iterator to one-past-last element
  /// @return new Span covering the range
  template<typename Iter> Span<Item> sub(Iter first, Iter last) {
    return Span<Item>(&*first, last - first);
  }

  /// @brief Get a subspan matching a predicate.
  /// @tparam F predicate type
  /// @tparam V element type (deduced)
  /// @param func predicate function
  /// @return new Span of contiguous elements matching the predicate
  template<typename F, typename V=Item> Span<V> subspan(F&& func) {
    iterator group_begin = std::find_if(this->begin(), this->end(), func);
    iterator group_end = std::find_if_not(group_begin, this->end(), func);
    return Span<V>(&*group_begin, group_end - group_begin);
  }
  /// @brief Get a const subspan matching a predicate.
  /// @tparam F predicate type
  /// @param func predicate function
  /// @return const Span of contiguous elements matching the predicate
  template<typename F> Span<const value_type> subspan(F&& func) const {
    using V = const value_type;
    return const_cast<Span*>(this)->subspan<F, V>(std::forward<F>(func));
  }

  /// @brief Get children (returns self for iteration protocol).
  Span& children() { return *this; }
  /// @brief Get const children (returns self for iteration protocol).
  const Span& children() const { return *this; }

private:
  iterator begin_ = nullptr;
  std::size_t size_ = 0;
};

/// @brief Span of std::vector that supports insert() and erase() operations.
template<typename Item> struct MutableVectorSpan : Span<Item> {
  using vector_type = std::vector<typename Span<Item>::value_type>;
  using iterator = typename Span<Item>::iterator;
  //friend Span<const value_type>;
  /// @brief Default constructor.
  MutableVectorSpan() = default;
  /// @brief Construct from span and vector pointer.
  /// @param p source span
  /// @param v pointer to underlying vector
  MutableVectorSpan(Span<Item>&& p, vector_type* v)
    : Span<Item>(p), vector_(v) {}
  /// @brief Construct from vector and element range.
  /// @param v the underlying vector
  /// @param begin iterator to first element in span
  /// @param n number of elements in span
  MutableVectorSpan(vector_type& v, iterator begin, std::size_t n)
    : Span<Item>(begin, n), vector_(&v) {}

  /// @brief Get a subspan from iterator range.
  /// @param first iterator to first element
  /// @param last iterator to one-past-last element
  /// @return new MutableVectorSpan covering the range
  template<typename Iter> MutableVectorSpan<Item> sub(Iter first, Iter last) {
    return {Span<Item>::sub(first, last), vector_};
  }

  /// @brief Get a mutable subspan matching a predicate.
  /// @param func predicate function
  /// @return new MutableVectorSpan of contiguous elements matching the predicate
  template<typename F> MutableVectorSpan<Item> subspan(F&& func) {
    return {Span<Item>::subspan(std::forward<F>(func)), vector_};
  }
  /// @brief Get a const subspan matching a predicate.
  /// @param func predicate function
  /// @return const MutableVectorSpan of contiguous elements matching the predicate
  template<typename F> MutableVectorSpan<const Item> subspan(F&& func) const {
    return {Span<const Item>::subspan(std::forward<F>(func)), vector_};
  }

  /// @brief Insert an element at the given position.
  /// @param pos iterator position for insertion
  /// @param item element to insert (moved)
  /// @return iterator to the newly inserted element
  iterator insert(iterator pos, Item&& item) {
    auto offset = this->begin_ - this->vector_->data();
    auto iter = vector_->begin() + (pos - this->vector_->data());
    auto ret = vector_->insert(iter, std::move(item));
    this->begin_ = vector_->data() + offset;
    ++this->size_;
    return &*ret;
  }

  /// @brief Erase the element at the given position.
  /// @param pos iterator to element to erase
  void erase(iterator pos) {
    vector_->erase(vector_->begin() + (pos - vector_->data()));
    --this->size_;
  }

  /// @brief Check if span starts at the beginning of the vector.
  bool is_beginning() const { return this->begin() == vector_->data(); }
  /// @brief Check if span extends to the end of the vector.
  bool is_ending() const { return this->end() == vector_->data() + vector_->size(); }

private:
  vector_type* vector_ = nullptr;  // for insert() and erase()
};

} // namespace gemmi
#endif

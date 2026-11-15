// Copyright 2018 Global Phasing Ltd.
//
// Bidirectional iterators (over elements of any container) that can filter,
// uniquify, group, or iterate with a stride.

#ifndef GEMMI_ITERATOR_HPP_
#define GEMMI_ITERATOR_HPP_
#include <iterator>     // for bidirectional_iterator_tag
#include <type_traits>  // for remove_cv
#include <vector>

namespace gemmi {

// Disable warning "X<T>::operator X<T>() const will not be called for
// implicit or explicit conversions", which is triggered when templates
// StrideIter, IndirectIter and others are expanded with const Value.
#if defined(__INTEL_COMPILER) || defined(__NVCOMPILER)
  #pragma diagnostic push
  #pragma diag_suppress = conversion_function_not_usable
#elif defined(__NVCC__)
  #pragma nv_diagnostic push
  #pragma nv_diag_suppress = conversion_function_not_usable
#endif

/// @brief Generic bidirectional iterator adapter implementing std::bidirectional_iterator_tag.
/// @tparam Policy the iteration policy class defining increment/decrement/dereference behavior
template <typename Policy>
struct BidirIterator : Policy {
  using value_type = typename std::remove_cv<typename Policy::value_type>::type;
  using difference_type = std::ptrdiff_t;
  using pointer = typename Policy::value_type*;
  using reference = typename Policy::reference;
  using iterator_category = std::bidirectional_iterator_tag;

  /// @brief Default constructor.
  BidirIterator() = default;
  /// @brief Construct from policy.
  /// @param p policy instance
  BidirIterator(Policy&& p) : Policy(p) {}

  /// @brief Pre-increment operator.
  BidirIterator& operator++() { Policy::increment(); return *this; }
  /// @brief Post-increment operator.
  BidirIterator operator++(int) { BidirIterator x = *this; ++*this; return x; }
  /// @brief Pre-decrement operator.
  BidirIterator& operator--() { Policy::decrement(); return *this; }
  /// @brief Post-decrement operator.
  BidirIterator operator--(int) { BidirIterator x = *this; --*this; return x; }
  /// @brief Equality comparison.
  bool operator==(const BidirIterator &o) const { return Policy::equal(o); }
  /// @brief Inequality comparison.
  bool operator!=(const BidirIterator &o) const { return !Policy::equal(o); }
  /// @brief Dereference operator.
  reference operator*() { return Policy::dereference(); }
  /// @brief Member access operator.
  pointer operator->() { return &Policy::dereference(); }
  using const_variant = BidirIterator<typename Policy::const_policy>;
  /// @brief Conversion to const variant iterator.
  operator const_variant() const {
    return const_variant(static_cast<const Policy&>(*this));
  }
};

/// @brief Policy for striding iterator that skips elements by a fixed stride.
template<typename Value>
class StrideIterPolicy {
public:
  using value_type = Value;
  using reference = Value&;
  /// @brief Default constructor.
  StrideIterPolicy() : cur_(nullptr), offset_(0), stride_(0) {}
  /// @brief Construct stride iterator policy.
  /// @param ptr pointer to data
  /// @param offset offset into current element
  /// @param stride stride distance (elements per step)
  StrideIterPolicy(Value* ptr, std::size_t offset, size_t stride)
    : cur_(ptr), offset_(offset), stride_((unsigned)stride) {}
  /// @brief Advance iterator by one stride.
  void increment() { cur_ += stride_; }
  /// @brief Move iterator back by one stride.
  void decrement() { cur_ -= stride_; }
  /// @brief Check iterator equality.
  bool equal(const StrideIterPolicy& o) const { return cur_ == o.cur_; }
  /// @brief Dereference to element.
  Value& dereference() { return cur_[offset_]; }
  using const_policy = StrideIterPolicy<Value const>;
  /// @brief Conversion to const policy.
  operator const_policy() const { return const_policy(cur_, offset_, stride_); }
private:
  Value* cur_;
  std::size_t offset_;
  unsigned stride_;
};
/// @brief Bidirectional iterator that strides through elements.
template<typename Value>
using StrideIter = BidirIterator<StrideIterPolicy<Value>>;


/// @brief Policy for indirect iterator that accesses elements through redirection.
template<typename Redirect, typename Value>
class IndirectIterPolicy {
public:
  using value_type = Value;
  using reference = Value&;
  /// @brief Default constructor.
  IndirectIterPolicy() : redir_(nullptr) {}
  /// @brief Construct indirect iterator policy.
  /// @param redir redirection object supporting value_at(int) method
  /// @param cur iterator into position vector
  IndirectIterPolicy(Redirect* redir, std::vector<int>::const_iterator cur)
    : redir_(redir), cur_(cur) {}
  /// @brief Advance to next position.
  void increment() { ++cur_; }
  /// @brief Move back to previous position.
  void decrement() { --cur_; }
  /// @brief Check iterator equality.
  bool equal(const IndirectIterPolicy& o) const { return cur_ == o.cur_; }
  /// @brief Dereference via redirection object.
  Value& dereference() { return redir_->value_at(*cur_); }
  using const_policy = IndirectIterPolicy<Redirect const, Value const>;
  /// @brief Conversion to const policy.
  operator const_policy() const { return const_policy(redir_, cur_); }
  // TODO: what should be done with absent optional tags (*cur_ < 0)?
private:
  Redirect* redir_;
  std::vector<int>::const_iterator cur_; // points into positions
};
/// @brief Bidirectional iterator that accesses elements indirectly through redirection.
template<typename Redirect, typename Value>
using IndirectIter = BidirIterator<IndirectIterPolicy<Redirect, Value>>;


/// @brief Policy for iterator that skips duplicate group keys.
template<typename Vector, typename Value>
class UniqIterPolicy {
public:
  using value_type = Value;
  using reference = Value&;
  /// @brief Default constructor.
  UniqIterPolicy() : vec_(nullptr), pos_(0) {}
  /// @brief Construct uniquifying iterator policy.
  /// @param vec vector with group_key() method on elements
  /// @param pos starting position
  UniqIterPolicy(Vector* vec, std::size_t pos) : vec_(vec), pos_(pos) {}
  /// @brief Move to the first element of the next group.
  void increment() {
    // move to the first element of the next group
    const auto& key = (*vec_)[pos_].group_key();
    ++pos_;
    while (pos_ != vec_->size() && (*vec_)[pos_].group_key() == key)
      ++pos_;
  }
  /// @brief Move back to the first element of the previous group.
  void decrement() {
    --pos_; // now we are at the last element of the previous group
    const auto& key = (*vec_)[pos_].group_key();
    while (pos_ != 0 && (*vec_)[pos_-1].group_key() == key)
      --pos_; // move to the group beginning
  }
  /// @brief Check iterator equality.
  bool equal(const UniqIterPolicy& o) const { return pos_ == o.pos_; }
  /// @brief Dereference to element.
  Value& dereference() { return (*vec_)[pos_]; }
  using const_policy = UniqIterPolicy<Vector const, Value const>;
  /// @brief Conversion to const policy.
  operator const_policy() const { return const_policy(vec_, pos_); }
private:
  Vector* vec_;
  std::size_t pos_;
};
/// @brief Bidirectional iterator that skips duplicate group keys.
template<typename Vector, typename Value>
using UniqIter = BidirIterator<UniqIterPolicy<Vector, Value>>;

/// @brief Range proxy for iterating with uniquification.
template<typename Value, typename Vector=std::vector<Value>>
struct UniqProxy {
  /// @brief The underlying vector.
  Vector& vec;
  using iterator = UniqIter<Vector, Value>;
  /// @brief Get begin iterator (first element).
  iterator begin() { return {{&vec, 0}}; }
  /// @brief Get end iterator (one past last element).
  iterator end() { return {{&vec, vec.size()}}; }
};
/// @brief Const range proxy for iterating with uniquification.
template<typename Value, typename Vector=std::vector<Value>>
struct ConstUniqProxy {
  /// @brief The underlying const vector.
  const Vector& vec;
  using iterator = UniqIter<const Vector, const Value>;
  /// @brief Get begin const iterator (first element).
  iterator begin() const { return {{&vec, 0}}; }
  /// @brief Get end const iterator (one past last element).
  iterator end() const { return {{&vec, vec.size()}}; }
};


/// @brief Policy for grouping iterator that returns spans of elements with matching group keys.
template<typename Vector, typename Value>
class GroupingIterPolicy {
public:
  using value_type = Value;
  using reference = Value&;
  /// @brief Default constructor.
  GroupingIterPolicy() = default;
  /// @brief Construct grouping iterator policy.
  /// @param span span object defining the range
  GroupingIterPolicy(const Value& span) : span_(span) {}
  /// @brief Advance to the next group.
  void increment() {
    span_.set_begin(span_.end());
    span_.set_size(0);
    while (!span_.is_ending() &&
           span_.begin()->group_key() == span_.end()->group_key())
      span_.set_size(span_.size() + 1);
  }
  /// @brief Move back to the previous group.
  void decrement() {
    span_.set_begin(span_.begin() - 1);
    span_.set_size(1);
    while (!span_.is_beginning() &&
           span_.begin()->group_key() == (span_.begin() - 1)->group_key()) {
      span_.set_begin(span_.begin() - 1);
      span_.set_size(span_.size() + 1);
    }
  }
  /// @brief Check iterator equality.
  bool equal(const GroupingIterPolicy& o) const {
    return span_.begin() == o.span_.begin();
  }
  /// @brief Dereference to span.
  Value& dereference() { return span_; }
  using const_policy = GroupingIterPolicy<Vector const, Value const>;
  /// @brief Conversion to const policy.
  operator const_policy() const { return const_policy(span_); }
private:
  Value span_;
};
/// @brief Bidirectional iterator that yields spans of elements with matching group keys.
template<typename Vector, typename Value>
using GroupingIter = BidirIterator<GroupingIterPolicy<Vector, Value>>;


/// @brief Policy for filtering iterator that selects elements matching a predicate.
template<typename Filter, typename Vector, typename Value>
class FilterIterPolicy {
public:
  using value_type = Value;
  using reference = Value&;
  /// @brief Default constructor.
  FilterIterPolicy() : vec_(nullptr), pos_(0) {}
  /// @brief Construct filtering iterator policy.
  /// @param filter filter object with matches(const Value&) method
  /// @param vec vector to filter
  /// @param pos starting position
  FilterIterPolicy(const Filter* filter, Vector* vec, std::size_t pos)
      : filter_(filter), vec_(vec), pos_(pos) {
    while (pos_ != vec_->size() && !matches(pos_))
      ++pos_;
  }
  /// @brief Check if element at position matches filter.
  bool matches(std::size_t p) const { return filter_->matches((*vec_)[p]); }
  /// @brief Advance to next matching element.
  void increment() { while (++pos_ < vec_->size() && !matches(pos_)) {} }
  /// @brief Move back to previous matching element.
  void decrement() { while (pos_ != 0 && !matches(--pos_)) {} }
  /// @brief Check iterator equality.
  bool equal(const FilterIterPolicy& o) const { return pos_ == o.pos_; }
  /// @brief Dereference to element.
  Value& dereference() { return (*vec_)[pos_]; }
  using const_policy = FilterIterPolicy<Filter, Vector const, Value const>;
  /// @brief Conversion to const policy.
  operator const_policy() const { return const_policy(vec_, pos_); }
private:
  const Filter* filter_;
  Vector* vec_;
  std::size_t pos_;
};
/// @brief Bidirectional iterator that filters elements matching a predicate.
template<typename Filter, typename Vector, typename Value>
using FilterIter = BidirIterator<FilterIterPolicy<Filter, Vector, Value>>;

/// @brief Range proxy for filtering iteration.
template<typename Filter, typename Value>
struct FilterProxy {
  /// @brief The filter predicate.
  const Filter& filter;
  /// @brief The underlying vector.
  std::vector<Value>& vec;
  using iterator = FilterIter<Filter, std::vector<Value>, Value>;
  /// @brief Get begin iterator (first matching element).
  iterator begin() { return {{&filter, &vec, 0}}; }
  /// @brief Get end iterator (one past last element).
  iterator end() { return {{&filter, &vec, vec.size()}}; }
};

/// @brief Const range proxy for filtering iteration.
template<typename Filter, typename Value>
struct ConstFilterProxy {
  /// @brief The filter predicate.
  const Filter& filter;
  /// @brief The underlying const vector.
  const std::vector<Value>& vec;
  using iterator = FilterIter<Filter, const std::vector<Value>, const Value>;
  /// @brief Get begin const iterator (first matching element).
  iterator begin() const { return {{&filter, &vec, 0}}; }
  /// @brief Get end const iterator (one past last element).
  iterator end() const { return {{&filter, &vec, vec.size()}}; }
};


/// @brief A group of items with the same group_key(), possibly sparse.
template<typename Item>
struct ItemGroup {
  using element_type = Item;

  /// @brief Construct a group from item range.
  /// @param start pointer to first item in the group
  /// @param end pointer to one-past-last item in the range
  /// @details Counts contiguous items with matching group_key() to determine size.
  ItemGroup(Item* start, const Item* end)
      : size_(int(end - start)), extent_(int(end - start)), start_(start) {
    for (const Item* i = start + 1; i != end; ++i)
      if (i->group_key() != start->group_key())
        --size_;
  }

  /// @brief Iterator for accessing sparse group items.
  struct iterator {
    /// @brief Pointer to current item.
    Item* ptr;
    /// @brief Pointer to one-past-last item in range.
    const Item* end;
    /// @brief Equality comparison.
    bool operator==(const iterator& o) const { return ptr == o.ptr; }
    /// @brief Inequality comparison.
    bool operator!=(const iterator& o) const { return ptr != o.ptr; }
    /// @brief Pre-increment operator.
    iterator& operator++() {
      const Item* prev = ptr++;
      while (ptr != end && ptr->group_key() != prev->group_key())
        ++ptr;
      return *this;
    }
    /// @brief Dereference operator.
    Item& operator*() { return *ptr; }
    /// @brief Member access operator.
    Item* operator->() { return ptr; }
  };
  /// @brief Get begin iterator.
  iterator begin() { return iterator{start_, start_+extent_}; }
  /// @brief Get end iterator.
  iterator end() { return iterator{start_+extent_, start_+extent_}; }

  /// @brief Get number of items with matching group_key() (sparse count).
  size_t size() const { return (size_t) size_; }
  /// @brief Get extent (total items in range, may include gaps).
  int extent() const { return extent_; }
  /// @brief Check if group is empty.
  bool empty() const { return size_ == 0; }
  /// @brief Access first item.
  Item& front() { return *start_; }
  /// @brief Access first item (const).
  const Item& front() const { return *start_; }
  /// @brief Access last item in extent.
  Item& back() { return start_[extent_ - 1]; }
  /// @brief Access last item in extent (const).
  const Item& back() const { return start_[extent_ - 1]; }

  /// @brief Access i-th item with matching group_key().
  /// @param i index within group
  /// @return reference to item
  /// @details O(1) if dense, O(i) if sparse (gap items with different key).
  Item& operator[](std::size_t i) {
    if (size_ == extent_ || i == 0)
      return start_[i];
    for (Item* ptr = start_ + 1; ; ++ptr)
      if (ptr->group_key() == start_->group_key())
        if (--i == 0)
          return *ptr;
  }
  /// @brief Access i-th item with matching group_key() (const).
  /// @param i index within group
  /// @return const reference to item
  const Item& operator[](std::size_t i) const {
    return const_cast<ItemGroup*>(this)->operator[](i);
  }

private:
  int size_ = 0;
  int extent_ = 0;
  Item* start_ = nullptr;
};

#if defined(__INTEL_COMPILER) || defined(__NVCOMPILER)
  #pragma diagnostic pop
#elif defined(__NVCC__)
  #pragma nv_diagnostic pop
#endif

} // namespace gemmi
#endif

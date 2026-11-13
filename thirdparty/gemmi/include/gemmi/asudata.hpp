// Copyright 2020 Global Phasing Ltd.
//
/// @file
/// @brief AsuData template for storing per-HKL reflection data in asymmetric unit.

#ifndef GEMMI_ASUDATA_HPP_
#define GEMMI_ASUDATA_HPP_

#include <complex>       // for arg, abs
#include <algorithm>     // for sort, is_sorted
#include "unitcell.hpp"
#include "symmetry.hpp"
#include "stats.hpp"     // for Correlation
#include "util.hpp"      // for vector_remove_if

namespace gemmi {

/// @brief Correlation calculation for complex-valued reflection data.
/// Accumulates running statistics for complex numbers (e.g., structure factors).
struct ComplexCorrelation {
  int n = 0;                          ///< Number of points accumulated
  double sum_xx = 0.;                 ///< Sum of |x|^2
  double sum_yy = 0.;                 ///< Sum of |y|^2
  std::complex<double> sum_xy = 0.;   ///< Sum of (x - mean_x) * conj(y - mean_y)
  std::complex<double> mean_x = 0.;   ///< Running mean of x
  std::complex<double> mean_y = 0.;   ///< Running mean of y
  /// @brief Add a complex-valued point pair to the correlation.
  /// @param x First complex value
  /// @param y Second complex value
  void add_point(std::complex<double> x, std::complex<double> y) {
    ++n;
    double inv_n = 1.0 / n;
    double weight = (n - 1.0) * inv_n;
    std::complex<double> dx = x - mean_x;
    std::complex<double> dy = y - mean_y;
    sum_xx += weight * std::norm(dx);
    sum_yy += weight * std::norm(dy);
    sum_xy += weight * (dx * std::conj(dy));
    mean_x += dx * inv_n;
    mean_y += dy * inv_n;
  }
  /// @brief Add a complex-valued point pair (float version).
  /// @param x First complex value
  /// @param y Second complex value
  void add_point(std::complex<float> x, std::complex<float> y) {
    add_point(std::complex<double>(x), std::complex<double>(y));
  }
  /// @brief Compute correlation coefficient from accumulated statistics.
  std::complex<double> coefficient() const { return sum_xy / std::sqrt(sum_xx * sum_yy); }
  /// @brief Compute ratio of mean magnitudes.
  double mean_ratio() const { return std::abs(mean_y) / std::abs(mean_x); }
};


/// @brief Apply a function to matching reflections from two sorted lists.
/// Iterates through reflections with matching HKLs in both lists and calls func.
/// @pre Vectors a and b are sorted by HKL.
/// @tparam Func Callable type taking (const T&, const T&).
/// @tparam T Reflection data type (must have hkl member and operator<).
/// @param a First reflection list.
/// @param b Second reflection list.
/// @param func Function to call for each matching pair.
template<typename Func, typename T>
void for_matching_reflections(const std::vector<T>& a,
                              const std::vector<T>& b,
                              const Func& func) {
  auto r1 = a.begin();
  auto r2 = b.begin();
  while (r1 != a.end() && r2 != b.end()) {
    if (r1->hkl == r2->hkl) {
      func(*r1, *r2);
      ++r1;
      ++r2;
    } else if (r1->hkl < r2->hkl) {
      ++r1;
    } else {
      ++r2;
    }
  }
}

/// @brief Calculate correlation of intensity values between two sorted lists.
/// @pre Vectors a and b are sorted by HKL.
/// @tparam T Reflection data type (must have hkl and value members).
/// @param a First reflection list.
/// @param b Second reflection list.
/// @return Correlation object computed from matching HKLs.
template<typename T>
Correlation calculate_hkl_value_correlation(const std::vector<T>& a,
                                            const std::vector<T>& b) {
  Correlation cor;
  for_matching_reflections(a, b, [&cor](const T& x, const T& y) {
      cor.add_point(x.value, y.value);
  });
  return cor;
}

/// @brief Calculate correlation of complex-valued reflection data between two sorted lists.
/// @pre Vectors a and b are sorted by HKL.
/// @tparam T Reflection data type (must have hkl and value members).
/// @param a First reflection list.
/// @param b Second reflection list.
/// @return ComplexCorrelation object computed from matching HKLs.
template<typename T>
ComplexCorrelation calculate_hkl_complex_correlation(const std::vector<T>& a,
                                                     const std::vector<T>& b) {
  ComplexCorrelation cor;
  for_matching_reflections(a, b, [&cor](const T& x, const T& y) {
      cor.add_point(x.value, y.value);
  });
  return cor;
}

/// @brief Count matching reflections with identical values in two sorted lists.
/// @pre Vectors a and b are sorted by HKL.
/// @tparam T Reflection data type (must have hkl and value members).
/// @param a First reflection list.
/// @param b Second reflection list.
/// @return Number of matching HKLs with equal values.
template<typename T>
int count_equal_values(const std::vector<T>& a, const std::vector<T>& b) {
  int count = 0;
  for_matching_reflections(a, b, [&count](const T& x, const T& y) {
      if (x.value == y.value)
        ++count;
  });
  return count;
}

/// @brief Miller index paired with a generic value.
/// Used as the basic element in AsuData containers.
/// @tparam T Value type (float, double, complex, etc.).
template<typename T>
struct HklValue {
  alignas(8) Miller hkl;  ///< Miller indices (h, k, l)
  T value;                ///< Associated value (intensity, structure factor, etc.)

  /// @brief Compare with Miller index.
  bool operator<(const Miller& m) const { return hkl < m; }
  /// @brief Compare with another HklValue by their HKL indices.
  bool operator<(const HklValue& o) const { return operator<(o.hkl); }
};

/// @brief Value paired with its uncertainty (sigma/standard deviation).
/// @tparam T Numeric type (float, double, etc.).
template<typename T>
struct ValueSigma {
  using value_type = T;
  T value;  ///< The measured or calculated value
  T sigma;  ///< Standard deviation or uncertainty

  /// @brief Check equality of both value and sigma.
  bool operator==(const ValueSigma& o) const {
    return value == o.value && sigma == o.sigma;
  }
};

/// @brief Implementation functions for moving reflections to asymmetric unit.
namespace impl {
/// @brief Generic move_to_asu for real-valued data (no phase adjustment).
template<typename T>
void move_to_asu(const GroupOps&, const Miller& hkl, int, HklValue<T>& hkl_value) {
  hkl_value.hkl = hkl;
}

/// @brief Specialized move_to_asu for complex-valued data (applies phase shift).
/// Applies phase shift from symmetry operator and conjugation for isym % 2 == 0.
template<typename R>
void move_to_asu(const GroupOps& gops, const Miller& hkl, int isym,
                 HklValue<std::complex<R>>& v) {
  v.hkl = hkl;
  // cf. Mtz::ensure_asu()
  const Op& op = gops.sym_ops[(isym - 1) / 2];
  double shift = op.phase_shift(hkl);
  if (shift != 0) {
    double phase = std::arg(v.value) + shift;
    v.value = std::polar(std::abs(v.value), (R)phase);
  }
  if (isym % 2 == 0)
    v.value.imag(-v.value.imag());
}
} // namespace impl

/// @brief Generic container for reflection data in asymmetric unit.
/// Stores values (e.g., structure factors, phases, intensities) indexed by Miller indices.
/// Keeps data sorted by HKL and can enforce ASU constraints.
/// @tparam T Value type (float, double, complex, ValueSigma<>, etc.).
template<typename T>
struct AsuData {
  std::vector<HklValue<T>> v;                  ///< Reflection data (HKL + value pairs)
  UnitCell unit_cell_;                        ///< Unit cell parameters
  const SpaceGroup* spacegroup_ = nullptr;    ///< Space group (not owned by this object)

  // FPhiProxy interface compatibility methods
  size_t stride() const { return 1; }
  size_t size() const { return v.size(); }
  Miller get_hkl(size_t n) const { return v[n].hkl; }
  double get_f(size_t n) const { return std::abs(v[n].value); }
  double get_phi(size_t n) const { return std::arg(v[n].value); }
  const UnitCell& unit_cell() const { return unit_cell_; }
  const SpaceGroup* spacegroup() const { return spacegroup_; }

  /// @brief Sort reflections by HKL indices if not already sorted.
  void ensure_sorted() {
    if (!std::is_sorted(v.begin(), v.end()))
      std::sort(v.begin(), v.end());
  }

  /// @brief Transform all reflections to the asymmetric unit.
  /// Moves reflections outside ASU to their equivalent inside, applying
  /// symmetry operators and phase shifts as needed for complex values.
  /// @param tnt_asu If true, use TNT-style ASU; otherwise use standard ASU.
  void ensure_asu(bool tnt_asu=false) {
    if (!spacegroup_)
      fail("AsuData::ensure_asu(): space group not set");
    GroupOps gops = spacegroup_->operations();
    ReciprocalAsu asu(spacegroup_, tnt_asu);
    for (HklValue<T>& hkl_value : v) {
      const Miller& hkl = hkl_value.hkl;
      if (asu.is_in(hkl))
        continue;
      auto result = asu.to_asu(hkl, gops);
      impl::move_to_asu(gops, result.first, result.second, hkl_value);
    }
  }

  /// @brief Load values from a single data column.
  /// Reads HKLs and values from proxy, filters NaN, converts to ASU, and sorts.
  /// @tparam DataProxy Type with column_index(), unit_cell(), spacegroup(),
  ///                    size(), stride(), get_hkl(), get_num() interface.
  /// @param proxy Data proxy object (MTZ, mmCIF, etc.).
  /// @param label Column name/label to load.
  /// @param as_is If true, skip ASU conversion and sorting (raw load).
  template<typename DataProxy>
  void load_values(const DataProxy& proxy, const std::string& label,
                   bool as_is=false) {
    std::size_t col = proxy.column_index(label);
    unit_cell_ = proxy.unit_cell();
    spacegroup_ = proxy.spacegroup();
    for (size_t i = 0; i < proxy.size(); i += proxy.stride()) {
      auto num = proxy.get_num(i + col);
      if (!std::isnan(num))
        v.push_back({proxy.get_hkl(i), (T)num});
    }
    if (!as_is) {
      ensure_asu();
      ensure_sorted();
    }
  }

  /// @brief Load values from multiple columns (for complex, vector, or sigma pairs).
  /// Reads N columns per reflection and combines them into a single value.
  /// Filters out reflections with any NaN in the N columns.
  /// @tparam N Number of columns to load (2 for complex/F+sigma, etc.).
  /// @tparam DataProxy Type with column_index(), unit_cell(), spacegroup(),
  ///                    size(), stride(), get_hkl(), get_num() interface.
  /// @param proxy Data proxy object (MTZ, mmCIF, etc.).
  /// @param labels Array of N column names/labels to load.
  /// @param as_is If true, skip ASU conversion and sorting (raw load).
  template<int N, typename DataProxy>
  void load_values(const DataProxy& proxy, const std::array<std::string,N>& labels,
                   bool as_is=false) {
    std::array<std::size_t, N> cols;
    for (int i = 0; i < N; ++i)
      cols[i] = proxy.column_index(labels[i]);
    unit_cell_ = proxy.unit_cell();
    spacegroup_ = proxy.spacegroup();
    using Val = typename T::value_type;
    for (size_t i = 0; i < proxy.size(); i += proxy.stride()) {
      std::array<Val, N> nums;
      for (int j = 0; j < N; ++j)
        nums[j] = (Val) proxy.get_num(i + cols[j]);
      if (!std::any_of(nums.begin(), nums.end(), [](Val f) { return std::isnan(f); })) {
        v.emplace_back();
        v.back().hkl = proxy.get_hkl(i);
        set_value_from_array(v.back().value, nums);
      }
    }
    if (!as_is) {
      ensure_asu();
      ensure_sorted();
    }
  }

private:
  /// @brief Helper to convert numeric array(s) to T.
  /// Overloaded for: scalar, array<1>, complex (F+phase), ValueSigma (F+sigma).
  static void set_value_from_array(T& val, const std::array<T,1>& nums) { val = nums[0]; }
  static void set_value_from_array(T& val, const T& nums) { val = nums; }
  /// @brief Convert (F, phi) pair to complex structure factor.
  template<typename R>
  static void set_value_from_array(std::complex<R>& val, const std::array<R,2>& nums) {
    R theta = (R)rad(nums[1]);
    val = {nums[0] * std::cos(theta), nums[0] * std::sin(theta)};
  }
  /// @brief Convert (value, sigma) pair to ValueSigma.
  template<typename R>
  static void set_value_from_array(ValueSigma<R>& val, const std::array<R,2>& nums) {
    val.value = nums[0];
    val.sigma = nums[1];
  }
};

/// @brief Create AsuData by loading from N columns in a data source.
/// @tparam T Value type to load into.
/// @tparam N Number of columns to combine per reflection.
/// @tparam Data Data source type (MTZ, mmCIF, etc.).
/// @param data Source data object.
/// @param labels Array of N column labels to load.
/// @param as_is If true, skip ASU conversion and sorting.
/// @return New AsuData object populated with data.
template<typename T, int N, typename Data>
AsuData<T> make_asu_data(const Data& data, const std::array<std::string,N>& labels,
                         bool as_is=false) {
  AsuData<T> asu_data;
  asu_data.template load_values<N>(data_proxy(data), labels, as_is);
  return asu_data;
}

/// @brief Create AsuData by loading from a single column in a data source.
/// @tparam T Value type to load into.
/// @tparam Data Data source type (MTZ, mmCIF, etc.).
/// @param data Source data object.
/// @param label Column label to load.
/// @param as_is If true, skip ASU conversion and sorting.
/// @return New AsuData object populated with data.
template<typename T, typename Data>
AsuData<T> make_asu_data(const Data& data, const std::string& label, bool as_is) {
  AsuData<T> asu_data;
  asu_data.load_values(data_proxy(data), label, as_is);
  return asu_data;
}

/// @brief Filter AsuData to retain only reflections with high signal-to-noise.
/// Removes reflections where sigma <= 0 or value/sigma < cutoff.
/// @tparam T Numeric type (float, double).
/// @param asu_data AsuData container with ValueSigma<T> values (in/out).
/// @param cutoff Minimum value/sigma ratio to retain.
template<typename T>
void discard_by_sigma_ratio(AsuData<ValueSigma<T>>& asu_data, double cutoff) {
  vector_remove_if(asu_data.v, [cutoff](const HklValue<ValueSigma<T>>& p) {
      auto& v = p.value;
      return v.sigma <= 0 || v.value <= cutoff * v.sigma;
  });
}

} // namespace gemmi
#endif

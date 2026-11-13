// Copyright 2018 Global Phasing Ltd.
//
// Statistics utilities: classes Covariance, Correlation, DataStats

#ifndef GEMMI_STATS_HPP_
#define GEMMI_STATS_HPP_

#include <cstddef>  // for size_t
#include <cmath>    // for sqrt, NAN, INFINITY
#include <vector>

namespace gemmi {

/// @brief Single-pass algorithm for calculating variance and mean
/// @details Uses Welford's algorithm for numerical stability.
///          Supports both initialization from iterators and incremental point addition.
struct Variance {
  int n = 0;           ///< Number of points added
  double sum_sq = 0.;  ///< Running sum of squared deviations
  double mean_x = 0.;  ///< Running mean

  Variance() = default;

  /// @brief Construct Variance from an iterator range
  /// @tparam T iterator type
  /// @param begin iterator to first element
  /// @param end iterator to one-past-last element
  template <typename T> Variance(T begin, T end) : Variance() {
    for (auto i = begin; i != end; ++i)
      add_point(*i);
  }

  /// @brief Add a single data point and update running statistics
  /// @param x the data value to add
  void add_point(double x) {
    ++n;
    double dx = x - mean_x;
    mean_x += dx / n;
    sum_sq += dx * (x - mean_x);
  }

  /// @brief Calculate sample variance (divide by n-1)
  /// @return sample variance
  double for_sample() const { return sum_sq / (n - 1); }

  /// @brief Calculate population variance (divide by n)
  /// @return population variance
  double for_population() const { return sum_sq / n; }
};

/// @brief Covariance of two variables using single-pass algorithm
/// @details Extends Variance to track covariance between paired (x, y) points.
struct Covariance : Variance {
  double mean_y = 0.; ///< Running mean of y values

  /// @brief Add a paired data point (x, y) and update running statistics
  /// @param x the x data value
  /// @param y the y data value
  void add_point(double x, double y) {
    ++n;
    double dx = x - mean_x;
    mean_x += dx / n;
    mean_y += (y - mean_y) / n;
    sum_sq += dx * (y - mean_y);
  }
};

/// @brief Correlation coefficient and regression statistics for paired data
/// @details Accumulates running statistics for two variables to compute
///          correlation coefficient, regression line (slope/intercept), and variances.
struct Correlation {
  int n = 0;          ///< Number of point pairs added
  double sum_xx = 0.; ///< Sum of weighted squared x deviations
  double sum_yy = 0.; ///< Sum of weighted squared y deviations
  double sum_xy = 0.; ///< Sum of weighted xy deviations
  double mean_x = 0.; ///< Running mean of x values
  double mean_y = 0.; ///< Running mean of y values

  /// @brief Add a paired data point (x, y) and update running statistics
  /// @param x the x data value
  /// @param y the y data value
  void add_point(double x, double y) {
    ++n;
    double weight = (double)(n - 1) / n;
    double dx = x - mean_x;
    double dy = y - mean_y;
    sum_xx += weight * dx * dx;
    sum_yy += weight * dy * dy;
    sum_xy += weight * dx * dy;
    mean_x += dx / n;
    mean_y += dy / n;
  }

  /// @brief Calculate Pearson correlation coefficient
  /// @return correlation coefficient (ranges from -1 to 1)
  double coefficient() const { return sum_xy / std::sqrt(sum_xx * sum_yy); }

  /// @brief Calculate variance of x values
  /// @return x variance
  double x_variance() const { return sum_xx / n; }

  /// @brief Calculate variance of y values
  /// @return y variance
  double y_variance() const { return sum_yy / n; }

  /// @brief Calculate covariance between x and y
  /// @return covariance
  double covariance() const { return sum_xy / n; }

  /// @brief Calculate ratio of means (mean_y / mean_x)
  /// @return ratio of means
  double mean_ratio() const { return mean_y / mean_x; }

  /// @brief Calculate slope of linear regression line (y = slope * x + intercept)
  /// @return regression slope
  double slope() const { return sum_xy / sum_xx; }

  /// @brief Calculate y-intercept of linear regression line
  /// @return regression intercept (y-value where x=0)
  double intercept() const { return mean_y - slope() * mean_x; }
};


/// @brief Combine two independent Correlation objects into one
/// @details Merges statistics from two separate correlation calculations
///          to produce a combined result as if all data had been processed together.
/// @param a the first Correlation object
/// @param b the second Correlation object
/// @return a new Correlation object with combined statistics
inline Correlation combine_two_correlations(const Correlation& a, const Correlation& b) {
  auto sq = [](double x) { return x * x; };
  Correlation r;
  r.n = a.n + b.n;
  r.mean_x = (a.n * a.mean_x + b.n * b.mean_x) / r.n;
  r.mean_y = (a.n * a.mean_y + b.n * b.mean_y) / r.n;
  r.sum_xx = a.sum_xx + a.n * sq(a.mean_x - r.mean_x)
           + b.sum_xx + b.n * sq(b.mean_x - r.mean_x);
  r.sum_yy = a.sum_yy + a.n * sq(a.mean_y - r.mean_y)
           + b.sum_yy + b.n * sq(b.mean_y - r.mean_y);
  r.sum_xy = a.sum_xy + a.n * (a.mean_x - r.mean_x) * (a.mean_y - r.mean_y)
           + b.sum_xy + b.n * (b.mean_x - r.mean_x) * (b.mean_y - r.mean_y);
  return r;
}

/// @brief Combine multiple Correlation objects into a single result
/// @param cors vector of Correlation objects to combine
/// @return a new Correlation object with combined statistics from all input correlations
inline Correlation combine_correlations(const std::vector<Correlation>& cors) {
  Correlation result;
  for (const Correlation& cor : cors)
    result = combine_two_correlations(result, cor);
  return result;
}


/// @brief Statistics describing a dataset (min, max, mean, RMS, NaN count)
struct DataStats {
  double dmin = NAN;     ///< Minimum value in the dataset
  double dmax = NAN;     ///< Maximum value in the dataset
  double dmean = NAN;    ///< Mean (average) value
  double rms = NAN;      ///< Root mean square (standard deviation)
  size_t nan_count = 0;  ///< Number of NaN values encountered
};

/// @brief Calculate statistical summary of a dataset
/// @details Computes min, max, mean, RMS, and counts NaN values.
///          For all-NaN inputs, min and max are set to NaN.
/// @tparam T numeric type of the data container
/// @param data vector of numeric values
/// @return DataStats object containing the calculated statistics
template<typename T>
DataStats calculate_data_statistics(const std::vector<T>& data) {
  DataStats stats;
  double sum = 0;
  double sq_sum = 0;
  stats.dmin = INFINITY;
  stats.dmax = -INFINITY;
  for (double d : data) {
    if (std::isnan(d)) {
      stats.nan_count++;
      continue;
    }
    sum += d;
    sq_sum += d * d;
    if (d < stats.dmin)
      stats.dmin = d;
    if (d > stats.dmax)
      stats.dmax = d;
  }
  if (stats.nan_count != data.size()) {
    stats.dmean = sum / (data.size() - stats.nan_count);
    stats.rms = std::sqrt(sq_sum / (data.size() - stats.nan_count) - stats.dmean * stats.dmean);
  } else {
    stats.dmin = NAN;
    stats.dmax = NAN;
  }
  return stats;
}

} // namespace gemmi
#endif

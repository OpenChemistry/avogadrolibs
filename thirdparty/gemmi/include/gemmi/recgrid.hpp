/// @file recgrid.hpp
/// @brief Reciprocal-space grid for reflection data and Fourier transforms.
///
/// This header provides ReciprocalGrid, a template class for storing complex-valued data
/// in reciprocal space indexed by Miller indices (h, k, l) or FFT grid coordinates.
/// Typically used to store structure factor amplitudes/phases or computed Fourier components.
/// The grid implements FFT conventions with half-l storage for Hermitian-symmetric data.

// Copyright 2020 Global Phasing Ltd.
//
// ReciprocalGrid -- grid for reciprocal space data.

#ifndef GEMMI_RECGRID_HPP_
#define GEMMI_RECGRID_HPP_

#include <memory>  // for unique_ptr
#include "asudata.hpp"
#include "grid.hpp"

namespace gemmi {

/// @brief Get the Friedel-mate value (complex conjugate for complex, identity for real).
/// @tparam T Real or complex type
/// @param v Input value
/// @return Complex conjugate if T is complex, otherwise @p v unchanged
template<typename T> T friedel_mate_value(T v) { return v; }
/// @brief Specialization: complex conjugate for Friedel mates.
template<typename T>
std::complex<T> friedel_mate_value(const std::complex<T>& v) {
  return std::conj(v);
}

/// @brief Grid for reciprocal-space (Fourier) data indexed by Miller indices.
/// @tparam T Data type at grid points (typically complex<float> or complex<double>)
///
/// Stores reflection amplitudes, phases, or structure factors in reciprocal space.
/// Indices u, v, w correspond to h, k, l (Miller indices) in the FFT grid.
/// For Hermitian-symmetric data (result of real-space FFT), can use half-l mode
/// to store only l >= 0, halving memory while allowing Friedel-mate reconstruction.
template<typename T>
struct ReciprocalGrid : GridBase<T> {
  bool half_l = false; ///< If true, stores only l>=0; l<0 values obtained from Friedel pairs

  /// @brief Check if Miller indices (u, v, w) are valid and in-range for the grid.
  /// @param u Grid index for h (may be negative in the range [-nu, nu))
  /// @param v Grid index for k (may be negative in the range [-nv, nv))
  /// @param w Grid index for l (may be negative in the range [-nw, nw), or [0, nw) if half_l)
  /// @return True if the indices are within valid range for this grid
  bool has_index(int u, int v, int w) const {
    bool half_u = (half_l && this->axis_order == AxisOrder::ZYX);
    bool half_w = (half_l && this->axis_order != AxisOrder::ZYX);
    return std::abs(half_u ? u : 2 * u) < this->nu &&
           std::abs(2 * v) < this->nv &&
           std::abs(half_w ? w : 2 * w) < this->nw;
  }
  /// @brief Check indices and throw if out of range.
  /// @param u Grid index for h
  /// @param v Grid index for k
  /// @param w Grid index for l
  /// @throws std::out_of_range if any index is invalid
  void check_index(int u, int v, int w) const {
    if (!has_index(u, v, w))
      throw std::out_of_range("ReciprocalGrid: index out of grid.");
  }
  /// @brief Compute flat array index from possibly-negative Miller indices.
  /// @param u Miller h index (range -nu <= u < nu)
  /// @param v Miller k index (range -nv <= v < nv)
  /// @param w Miller l index (range -nw <= w < nw or 0 <= w < nw with half_l)
  /// @return Flat array index with periodic wrapping applied
  size_t index_n(int u, int v, int w) const {
    return this->index_q(u >= 0 ? u : u + this->nu,
                         v >= 0 ? v : v + this->nv,
                         w >= 0 ? w : w + this->nw);
  }
  /// @brief Compute checked and wrapped index from Miller indices.
  /// @param u Miller h index
  /// @param v Miller k index
  /// @param w Miller l index
  /// @return Flat array index after bounds checking and wrapping
  /// @throws std::out_of_range if indices are invalid
  size_t index_checked(int u, int v, int w) const {
    check_index(u, v, w);
    return index_n(u, v, w);
  }
  /// @brief Get value at Miller indices with bounds checking.
  /// @param u Miller h index
  /// @param v Miller k index
  /// @param w Miller l index
  /// @return The value at (u, v, w)
  /// @throws std::out_of_range if indices are out of range
  T get_value(int u, int v, int w) const {
    return this->data[index_checked(u, v, w)];
  }
  /// @brief Get value at Miller indices, returning default T{} if out of range.
  /// @param u Miller h index
  /// @param v Miller k index
  /// @param w Miller l index
  /// @return The value at (u, v, w), or T{} (zero) if indices are invalid
  T get_value_or_zero(int u, int v, int w) const {
    return has_index(u, v, w) ? this->data[index_n(u, v, w)] : T{};
  }
  /// @brief Set value at Miller indices with bounds checking.
  /// @param u Miller h index
  /// @param v Miller k index
  /// @param w Miller l index
  /// @param x The value to store
  /// @throws std::out_of_range if indices are out of range
  void set_value(int u, int v, int w, T x) {
    this->data[index_checked(u, v, w)] = x;
  }
  /// @brief Convert grid Point (with u, v, w indices) to Miller indices (h, k, l).
  /// @param point Point from grid iteration with normalized indices [0, n)
  /// @return Miller index vector accounting for FFT conventions and axis order
  Miller to_hkl(const typename GridBase<T>::Point& point) const {
    Miller hkl{{point.u, point.v, point.w}};
    if (2 * point.u >= this->nu &&
        !(half_l && this->axis_order == AxisOrder::ZYX))
      hkl[0] -= this->nu;
    if (2 * point.v >= this->nv)
      hkl[1] -= this->nv;
    if (2 * point.w >= this->nw &&
        !(half_l && this->axis_order != AxisOrder::ZYX))
      hkl[2] -= this->nw;
    if (this->axis_order == AxisOrder::ZYX)
      std::swap(hkl[0], hkl[2]);
    return hkl;
  }

  /// @brief Compute 1/d^2 resolution from a grid point (inverse d-spacing squared).
  /// @param point Grid point with u, v, w indices
  /// @return 1/d^2 in reciprocal Angstrom units
  double calculate_1_d2(const typename GridBase<T>::Point& point) const {
    return this->unit_cell.calculate_1_d2(to_hkl(point));
  }
  /// @brief Compute d-spacing for a grid point.
  /// @param point Grid point with u, v, w indices
  /// @return d-spacing (resolution) in Angstroms
  double calculate_d(const typename GridBase<T>::Point& point) const {
    return this->unit_cell.calculate_d(to_hkl(point));
  }

  /// @brief Get reflection value by Miller indices with optional post-processing.
  /// @param hkl Miller indices (h, k, l)
  /// @param unblur Sharpening factor (B-factor correction); 0 = no sharpening
  /// @param mott_bethe If true, apply Mott-Bethe factor for scattering angle dependence
  /// @return Value at (h, k, l), with Friedel mate retrieval if half_l is set and l<0,
  ///         and post-processing applied (unblur/Mott-Bethe)
  /// @note For half_l grids with negative l, fetches the Friedel conjugate at (-h,-k,-l)
  T get_value_by_hkl(Miller hkl, double unblur=0,
                     bool mott_bethe=false) const {
    if (this->axis_order == AxisOrder::ZYX)
      fail("get_value_by_hkl(): ZYX order is not supported yet");
    T value;
    if (half_l && hkl[2] < 0)
      value = friedel_mate_value(this->get_value(-hkl[0], -hkl[1], -hkl[2]));
    else
      value = this->get_value(hkl[0], hkl[1], hkl[2]);

    if (unblur != 0. || mott_bethe) {
      double inv_d2 = this->unit_cell.calculate_1_d2(hkl);
      double mult = 1;
      if (unblur != 0)
        mult = std::exp(unblur * 0.25 * inv_d2);
      if (mott_bethe)
        mult *= -mott_bethe_const() / inv_d2;
      value *= static_cast<decltype(std::abs(value))>(mult);
    }
    return value;
  }

  /// @brief Extract reflection data in asymmetric unit (ASU) sorted by Miller indices.
  /// @tparam R Output data type (default: same as grid type T)
  /// @param dmin Minimum resolution cutoff (Angstroms); 0 = no cutoff
  /// @param unblur B-factor sharpening/blurring factor
  /// @param with_000 If true, include the origin reflection (0,0,0)
  /// @param with_sys_abs If true, include systematically absent reflections
  /// @param mott_bethe If true, apply Mott-Bethe factor correction
  /// @return AsuData object with reflections in the asymmetric unit, sorted by (h,k,l)
  /// @note For half_l grids, automatically retrieves Friedel mates for l<0
  // the result is always sorted by h,k,l
  template <typename R=T>
  AsuData<R> prepare_asu_data(double dmin=0, double unblur=0,
                              bool with_000=false, bool with_sys_abs=false,
                              bool mott_bethe=false) {
    AsuData<R> asu_data;
    if (this->axis_order == AxisOrder::ZYX)
      fail("get_asu_values(): ZYX order is not supported yet");
    int max_h = (this->nu - 1) / 2;
    int max_k = (this->nv - 1) / 2;
    int max_l = half_l ? this->nw - 1 : (this->nw - 1) / 2;
    double max_1_d2 = 0.;
    if (dmin != 0.) {
      max_1_d2 = 1. / (dmin * dmin);
      Miller lim = this->unit_cell.get_hkl_limits(dmin);
      max_h = std::min(max_h, lim[0]);
      max_k = std::min(max_k, lim[1]);
      max_l = std::min(max_l, lim[2]);
    }
    gemmi::ReciprocalAsu asu(this->spacegroup);
    std::unique_ptr<GroupOps> gops;
    if (!with_sys_abs && this->spacegroup)
      gops.reset(new GroupOps(this->spacegroup->operations()));
    Miller hkl;
    for (hkl[0] = -max_h; hkl[0] <= max_h; ++hkl[0]) {
      int hi = hkl[0] >= 0 ? hkl[0] : hkl[0] + this->nu;
      int hi_ = -hkl[0] >= 0 ? -hkl[0] : -hkl[0] + this->nu;
      for (hkl[1] = -max_k; hkl[1] <= max_k; ++hkl[1]) {
        hkl[2] = -max_l;
        // (hkl)s with l<0 might be needed to get complete asu.
        // If they are absent in the data (Hermitian FFT), use Friedel's pairs.
        if (half_l) {
          int ki_ = -hkl[1] >= 0 ? -hkl[1] : -hkl[1] + this->nv;
          for (; hkl[2] < 0; ++hkl[2])
            if (asu.is_in(hkl) &&
                (max_1_d2 == 0. || this->unit_cell.calculate_1_d2(hkl) < max_1_d2) &&
                (with_sys_abs || !gops->is_systematically_absent(hkl)))
              asu_data.v.push_back({hkl,
                  friedel_mate_value(this->get_value_q(hi_, ki_, -hkl[2]))});
        }
        int ki = hkl[1] >= 0 ? hkl[1] : hkl[1] + this->nv;
        for (; hkl[2] <= max_l; ++hkl[2])
          if (asu.is_in(hkl) &&
              (max_1_d2 == 0. || this->unit_cell.calculate_1_d2(hkl) < max_1_d2) &&
              (with_sys_abs || !gops->is_systematically_absent(hkl)) &&
              (with_000 || !(hkl[0] == 0 && hkl[1] == 0 && hkl[2] == 0))) {
            int li = hkl[2] >= 0 ? hkl[2] : hkl[2] + this->nw;
            asu_data.v.push_back({hkl, this->get_value_q(hi, ki, li)});
          }
      }
    }
    if (unblur != 0. || mott_bethe)
      for (HklValue<R>& hv : asu_data.v) {
        double inv_d2 = this->unit_cell.calculate_1_d2(hv.hkl);
        double mult = 1;
        if (unblur != 0)
          // cf. reciprocal_space_multiplier()
          mult = std::exp(unblur * 0.25 * inv_d2);
        if (mott_bethe)
          // cf. mott_bethe_factor
          mult *= -mott_bethe_const() / inv_d2;
        hv.value *= static_cast<decltype(std::abs(hv.value))>(mult);
      }
    asu_data.unit_cell_ = this->unit_cell;
    asu_data.spacegroup_ = this->spacegroup;
    return asu_data;
  }
};

/// @brief Convenience alias for a reciprocal grid of complex F (magnitude/phase) values.
/// @tparam T Floating-point precision (float or double)
template<typename T> using FPhiGrid = ReciprocalGrid<std::complex<T>>;

} // namespace gemmi
#endif

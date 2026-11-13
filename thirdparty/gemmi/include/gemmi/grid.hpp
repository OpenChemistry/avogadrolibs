/// @file grid.hpp
/// @brief 3D crystallographic grids for electron density maps, cell-method search, and reflection data.
///
/// This header provides template classes for regular 3D grids on a crystallographic unit cell,
/// with support for symmetry operations, interpolation (trilinear and tricubic),
/// and operations on grid points within specified regions or radii.

// Copyright 2017 Global Phasing Ltd.
//
// 3d grids used by CCP4 maps, cell-method search and hkl data.

#ifndef GEMMI_GRID_HPP_
#define GEMMI_GRID_HPP_

#include <cassert>
#include <cstddef>    // for ptrdiff_t
#include <complex>
#include <algorithm>  // for fill
#include <numeric>    // for accumulate
#include <type_traits>
#include <vector>
#include "unitcell.hpp"
#include "symmetry.hpp"
#include "stats.hpp"  // for DataStats
#include "fail.hpp"   // for fail

namespace gemmi {

/// @brief Order of grid axes relative to unit cell axes (a, b, c).
///
/// Not all functionality works with all axis orders; many operations require XYZ order.
/// The values XYZ and ZYX are used only when the grid covers the whole unit cell.
enum class AxisOrder : unsigned char {
  Unknown,  ///< Axis order not determined
  XYZ,      ///< Grid axes correspond to a, b, c (default, CCP4 convention).
            ///< Index X (H in reciprocal space) varies fastest; Z (or L) varies slowest.
  ZYX       ///< Grid axes reversed: Z varies fastest, X varies slowest.
            ///< May not be fully supported everywhere.
};

/// @brief Strategy for rounding calculated grid dimensions to suitable values.
enum class GridSizeRounding {
  Nearest,  ///< Round to nearest value with small prime factors (2, 3, 5).
  Up,       ///< Round up (ceil) to next value with small prime factors.
  Down      ///< Round down (floor) to previous value with small prime factors.
};

/// @brief Compute mathematical modulo (a mod n), always returning a value in [0, n).
/// @param a value to take modulo
/// @param n modulus (n > 0)
/// @return Value in range [0, n)
inline int modulo(int a, int n) {
  if (a >= n)
    a %= n;
  else if (a < 0)
    a = (a + 1) % n + n - 1;
  return a;
}

/// @brief Check if n has only small prime factors (2, 3, 5).
/// @param n Integer to check
/// @return True if n = 2^a * 3^b * 5^c for non-negative a, b, c
inline bool has_small_factorization(int n) {
  while (n % 2 == 0)
    n /= 2;
  for (int k : {3, 5})
    while (n % k == 0)
      n /= k;
  return n == 1 || n == -1;
}

/// @brief Round a value to the nearest integer with only small prime factors.
///
/// Useful for choosing FFT-friendly grid dimensions.
/// @param exact Exact floating-point value
/// @param rounding Rounding strategy (Up, Down, or Nearest)
/// @return Integer >= 1 with only 2, 3, 5 as prime factors, closest to @p exact per the strategy
inline int round_with_small_factorization(double exact, GridSizeRounding rounding) {
  int n;
  if (rounding == GridSizeRounding::Up) {
    n = int(std::ceil(exact));
    while (!has_small_factorization(n))
      ++n;
  } else if (rounding == GridSizeRounding::Down) {
    n = std::max(int(std::floor(exact)), 1);
    while (!has_small_factorization(n))
      --n;
  } else {  // GridSizeRounding::Nearest
    n = int(std::round(exact));
    int sign = n > exact ? -1 : 1;
    int k = 1;
    while (n <= 0 || !has_small_factorization(n)) {
      // for sign=1 we want sequence n+1, n-1, n+2, n-2, n+3, ...
      n += sign * k;
      sign = -sign;
      ++k;
    }
  }
  return n;
}

/// @brief Compute suitable grid dimensions respecting space group symmetry and FFT efficiency.
///
/// Takes into account space group symmetry factors and symmetry-related directions
/// (which must have equal grid sizes), and rounds to dimensions with small prime factors.
/// @param limit Target grid dimensions (approximate)
/// @param rounding Rounding strategy for each dimension
/// @param sg Space group constraints (may be null for P1)
/// @return Array of three grid dimensions {nu, nv, nw}
inline std::array<int, 3> good_grid_size(std::array<double, 3> limit,
                                         GridSizeRounding rounding,
                                         const SpaceGroup* sg) {
  std::array<int, 3> m = {{0, 0, 0}};
  GroupOps gops;
  if (sg)
    gops = sg->operations();
  std::array<int, 3> sg_fac = gops.find_grid_factors();

  // If two dimensions are symmetry-related, they must have the same size.
  // Otherwise, if two dimensions are almost equal, the same grid size
  // looks better and is preferred.
  for (int i = 1; i < 3; ++i)
    for (int j = 0; j < i; ++j)
      if (gops.are_directions_symmetry_related(i, j) ||
          (std::fabs(limit[i] - limit[j]) < 0.5 && sg_fac[i] == sg_fac[j])) {
        if (rounding == GridSizeRounding::Up)
          limit[j] = std::max(limit[i], limit[j]);
        else if (rounding == GridSizeRounding::Down)
          limit[j] = std::min(limit[i], limit[j]);
        else // GridSizeRounding::Nearest
          limit[j] = 0.5 * (limit[i] + limit[j]);
        sg_fac[i] = -j;  // mark the dimension with higher index
      }

  for (int i = 0; i < 3; ++i) {
    int f = sg_fac[i];
    if (f > 0) {  // need to calculate the size
      if (f % 2 != 0)
        f *= 2; // always use even sizes - it simplifies things
      m[i] = f * round_with_small_factorization(limit[i] / f, rounding);
    } else { // the same size was already calculated
      m[i] = m[-f];
    }
  }
  return m;
}

/// @brief A crystallographic symmetry operation scaled for grid coordinates.
///
/// The scaled operation directly transforms grid indices by applying the
/// rotation matrix and scaled translation (pre-scaled by grid dimensions).
struct GridOp {
  Op scaled_op;  ///< Crystallographic operation with translation scaled to grid coordinates

  /// @brief Apply the operation to grid indices.
  /// @param u Grid index along first axis
  /// @param v Grid index along second axis
  /// @param w Grid index along third axis
  /// @return Transformed grid indices {u', v', w'}
  std::array<int, 3> apply(int u, int v, int w) const {
    std::array<int, 3> t;
    const Op::Rot& rot = scaled_op.rot;
    for (int i = 0; i != 3; ++i)
      t[i] = rot[i][0] * u + rot[i][1] * v + rot[i][2] * w + scaled_op.tran[i];
    return t;
  }
};

/// @brief Verify that grid dimensions are compatible with space group symmetry.
///
/// Checks that each dimension is divisible by the corresponding space group factor,
/// and that symmetry-related directions have equal grid sizes.
/// @param sg Space group to validate against (may be null for P1)
/// @param size Grid dimensions {nu, nv, nw}
/// @throws Raises an exception if constraints are violated
inline void check_grid_factors(const SpaceGroup* sg, std::array<int,3> size) {
  if (sg) {
    GroupOps gops = sg->operations();
    auto factors = gops.find_grid_factors();
    for (int i = 0; i != 3; ++i)
      if (size[i] % factors[i] != 0)
        fail("Grid not compatible with the space group " + sg->xhm());
    for (int i = 1; i != 3; ++i)
      for (int j = 0; j != i; ++j)
        if (gops.are_directions_symmetry_related(i, j) && size[i] != size[j])
          fail("Grid must have the same size in symmetry-related directions");
  }
}

/// @brief Linear interpolation (lerp) between two values.
/// @param a Start value
/// @param b End value
/// @param t Interpolation parameter in [0, 1]; 0 returns a, 1 returns b
/// @return Interpolated value a + (b - a) * t
inline double lerp_(double a, double b, double t) {
  return a + (b - a) * t;
}

/// @brief Linear interpolation for complex numbers.
template<typename T>
std::complex<T> lerp_(std::complex<T> a, std::complex<T> b, double t) {
  return a + (b - a) * (T) t;
}

/// @brief Catmull–Rom cubic spline interpolation.
/// @details Interpolates a cubic between points b and c given neighboring points a and d.
/// Uses the Catmull–Rom formula (equation 24 in the reference below).
/// @param u Parameter in [0, 1], where 0 → b, 1 → c
/// @param a Value at u = -1
/// @param b Value at u = 0
/// @param c Value at u = 1
/// @param d Value at u = 2
/// @return Interpolated value
/// @par References
/// Afonine, P.V., Poon, B.K., Read, R.J., Sobolev, O.V., Terwilliger, T.C.,
/// Urzhumtsev, A. & Adams, P.D. (2018). Real-space refinement in PHENIX for
/// cryo-EM and crystallography. Acta Cryst. D74, 531–544.
/// https://doi.org/10.1107/S2059798318006551
inline double cubic_interpolation(double u, double a, double b, double c, double d) {
  //return 0.5 * u * (u * (u * (3*b - 3*c + d - a) + (2*a - 5*b + 4*c - d)) + (c - a)) + b;
  // equivalent form that is faster on my computer:
  return -0.5 * (a * u * ((u-2)*u + 1) - b * ((3*u - 5) * u*u + 2) +
                 u * (c * ((3*u - 4) * u - 1) - d * (u-1) * u));
}

/// @brief First derivative of cubic spline interpolation.
///
/// Computes df/du for Catmull–Rom interpolation.
/// @param u Parameter in [0, 1]
/// @param a Value at u = -1
/// @param b Value at u = 0
/// @param c Value at u = 1
/// @param d Value at u = 2
/// @return df/du at parameter u
inline double cubic_interpolation_der(double u, double a, double b, double c, double d) {
  return a * (-1.5*u*u + 2*u - 0.5) + c * (-4.5*u*u + 4*u + 0.5)
         + u * (4.5*b*u - 5*b + 1.5*d*u - d);
}


/// @brief Metadata common to all grid types (not dependent on stored data type).
///
/// Contains unit cell, space group, grid dimensions, and indexing operations.
/// Grid indices u, v, w are in the range [0, nu), [0, nv), [0, nw) for valid grids.
struct GridMeta {
  UnitCell unit_cell;           ///< Unit cell of the crystal
  const SpaceGroup* spacegroup = nullptr;  ///< Space group (may be nullptr for P1)
  int nu = 0, nv = 0, nw = 0;  ///< Grid dimensions
  AxisOrder axis_order = AxisOrder::Unknown;  ///< Grid axis correspondence to a, b, c

  /// @brief Total number of grid points.
  /// @return nu * nv * nw
  size_t point_count() const { return (size_t)nu * nv * nw; }

  /// @brief Convert grid indices to fractional coordinates.
  ///
  /// @param u Grid index (not normalized to [0, 1))
  /// @param v Grid index (not normalized to [0, 1))
  /// @param w Grid index (not normalized to [0, 1))
  /// @return Fractional coordinates {u/nu, v/nv, w/nw}
  Fractional get_fractional(int u, int v, int w) const {
    return {u * (1.0 / nu), v * (1.0 / nv), w * (1.0 / nw)};
  }

  /// @brief Convert grid indices to orthogonal (Cartesian) coordinates.
  /// @param u Grid index
  /// @param v Grid index
  /// @param w Grid index
  /// @return Orthogonal position in Angstroms
  Position get_position(int u, int v, int w) const {
    return unit_cell.orthogonalize(get_fractional(u, v, w));
  }

  /// @brief Get symmetry operations scaled to grid coordinates (excluding identity).
  ///
  /// Returns all non-identity symmetry operations with translations and rotations
  /// pre-scaled for direct application to grid indices. Used internally for
  /// symmetrization operations. Requires axis_order == AxisOrder::XYZ.
  /// @return Vector of GridOp, empty if space group is P1
  /// @throws Raises exception if grid is not in XYZ order
  std::vector<GridOp> get_scaled_ops_except_id() const {
    std::vector<GridOp> grid_ops;
    if (!spacegroup || spacegroup->number == 1)
      return grid_ops;
    if (axis_order != AxisOrder::XYZ)
      fail("grid can use symmetries only if it is setup in the XYZ order");
    GroupOps gops = spacegroup->operations();
    grid_ops.reserve(gops.order());
    for (const Op& so : gops.sym_ops)
      for (const Op::Tran& co : gops.cen_ops) {
        Op op = so.add_centering(co);
        if (op != Op::identity()) {
          // Rescale. Rotations are expected to be integral.
          op.tran[0] = op.tran[0] * nu / Op::DEN;
          op.tran[1] = op.tran[1] * nv / Op::DEN;
          op.tran[2] = op.tran[2] * nw / Op::DEN;
          for (int i = 0; i != 3; ++i)
            for (int j = 0; j != 3; ++j)
              op.rot[i][j] /= Op::DEN;
          grid_ops.push_back({op});
        }
      }
    return grid_ops;
  }

  /// @brief Quick index computation: fastest but requires 0 <= u < nu, etc.
  ///
  /// No bounds checking. Data layout is row-major: (w*nv + v)*nu + u.
  /// @param u Grid index (must be in [0, nu))
  /// @param v Grid index (must be in [0, nv))
  /// @param w Grid index (must be in [0, nw))
  /// @return Index into flat data array
  size_t index_q(int u, int v, int w) const {
    return size_t(w * nv + v) * nu + u;
  }

  /// @brief Quick index computation for unsigned indices.
  size_t index_q(size_t u, size_t v, size_t w) const {
    return (w * nv + v) * nu + u;
  }

  /// @brief Index with periodic wrapping: faster than index_s() but limited range.
  ///
  /// Works for indices in the range [-nu, 2*nu) (and similarly for v, w).
  /// Applies periodic boundary conditions (wraps to [0, n)).
  /// @param u Grid index
  /// @param v Grid index
  /// @param w Grid index
  /// @return Index into flat data array
  size_t index_n(int u, int v, int w) const { return index_n_ref(u, v, w); }

  /// @brief Index with periodic wrapping, modifying arguments in-place.
  ///
  /// Same as index_n() but normalizes u, v, w to [0, nu), [0, nv), [0, nw).
  /// @param u Grid index (will be normalized)
  /// @param v Grid index (will be normalized)
  /// @param w Grid index (will be normalized)
  /// @return Index into flat data array
  size_t index_n_ref(int& u, int& v, int& w) const {
    if (u >= nu) u -= nu; else if (u < 0) u += nu;
    if (v >= nv) v -= nv; else if (v < 0) v += nv;
    if (w >= nw) w -= nw; else if (w < 0) w += nw;
    return this->index_q(u, v, w);
  }

  /// @brief Index with periodic wrapping for indices near zero.
  ///
  /// Optimized version of index_n() for indices in [-n, n).
  /// @param u Grid index in range [-nu, nu)
  /// @param v Grid index in range [-nv, nv)
  /// @param w Grid index in range [-nw, nw)
  /// @return Index into flat data array
  size_t index_near_zero(int u, int v, int w) const {
    return this->index_q(u >= 0 ? u : u + nu,
                         v >= 0 ? v : v + nv,
                         w >= 0 ? w : w + nw);
  }
};

/// @brief Common base for Grid and ReciprocalGrid templates.
/// @tparam T Data type stored at each grid point
template<typename T>
struct GridBase : GridMeta {
  /// @brief A grid point with normalized indices and a value pointer.
  ///
  /// Indices u, v, w have been normalized to [0, nu), [0, nv), [0, nw).
  /// The pointer may become invalid if the grid is resized.
  struct Point {
    int u, v, w;   ///< Normalized grid indices
    T* value;      ///< Pointer to the grid value at this point
  };

  std::vector<T> data;  ///< Flat row-major array of grid values

  /// @brief Check that grid is not empty (has allocated data).
  /// @throws Raises exception if data.empty()
  void check_not_empty() const {
    if (data.empty())
      fail("grid is empty");
  }

  /// @brief Allocate and set grid dimensions without bounds checking.
  ///
  /// Resizes the data array to nu_ * nv_ * nw_ elements.
  /// Does not validate space group compatibility.
  /// @param nu_ Number of grid points along first axis
  /// @param nv_ Number of grid points along second axis
  /// @param nw_ Number of grid points along third axis
  void set_size_without_checking(int nu_, int nv_, int nw_) {
    nu = nu_, nv = nv_, nw = nw_;
    data.resize((size_t)nu_ * nv_ * nw_);
  }

  /// @brief Get value at grid point using quick (unsafe) index.
  /// @param u Grid index (must be in [0, nu))
  /// @param v Grid index (must be in [0, nv))
  /// @param w Grid index (must be in [0, nw))
  /// @return Value at (u, v, w)
  T get_value_q(int u, int v, int w) const { return data[index_q(u, v, w)]; }

  /// @brief Convert a Point to its index in the data array.
  /// @param p Point with value pointer
  /// @return Index into data array
  size_t point_to_index(const Point& p) const { return p.value - data.data(); }

  /// @brief Convert a data array index to a Point with normalized indices.
  /// @param idx Index into data array
  /// @return Point with indices and value pointer
  Point index_to_point(size_t idx) {
    auto d1 = std::div((ptrdiff_t)idx, (ptrdiff_t)nu);
    auto d2 = std::div(d1.quot, (ptrdiff_t)nv);
    int u = (int) d1.rem;
    int v = (int) d2.rem;
    int w = (int) d2.quot;
    assert(index_q(u, v, w) == idx);
    return {u, v, w, &data.at(idx)};
  }

  /// @brief Resize grid and fill all points with a constant value.
  /// @param value Value to assign to all grid points
  void fill(T value) {
    data.resize(point_count());
    std::fill(data.begin(), data.end(), value);
  }

  /// @brief Sum type used for accumulating values (ptrdiff_t for integers, T for floats).
  using Tsum = typename std::conditional<std::is_integral<T>::value,
                                         std::ptrdiff_t, T>::type;
  /// @brief Sum all grid values.
  /// @return Sum of all data points
  Tsum sum() const { return std::accumulate(data.begin(), data.end(), Tsum()); }


  /// @brief Iterator over grid points in row-major order (u varies fastest).
  struct iterator {
    GridBase& parent;      ///< Reference to parent grid
    size_t index;          ///< Current position in data array
    int u = 0, v = 0, w = 0;  ///< Current grid coordinates

    /// @brief Construct an iterator at a specific index.
    iterator(GridBase& parent_, size_t index_)
      : parent(parent_), index(index_) {}

    /// @brief Pre-increment to next grid point.
    iterator& operator++() {
      ++index;
      if (++u == parent.nu) {
        u = 0;
        if (++v == parent.nv) {
          v = 0;
          ++w;
        }
      }
      return *this;
    }

    /// @brief Dereference to a Point at current position.
    typename GridBase<T>::Point operator*() {
      return {u, v, w, &parent.data[index]};
    }

    /// @brief Equality comparison.
    bool operator==(const iterator &o) const { return index == o.index; }

    /// @brief Inequality comparison.
    bool operator!=(const iterator &o) const { return index != o.index; }
  };

  /// @brief Begin iterator (first grid point).
  iterator begin() { return {*this, 0}; }

  /// @brief End iterator (one past last grid point).
  iterator end() { return {*this, data.size()}; }
};

/// @brief Real-space crystallographic grid (electron density, masks, etc.).
/// @tparam T Data type for grid values (default: float)
///
/// A 3D grid covering the unit cell at regular fractional intervals.
/// Grid points are at fractional coordinates (i/nu, j/nv, k/nw).
/// Many operations require AxisOrder::XYZ and covering the full unit cell.
template<typename T=float>
struct Grid : GridBase<T> {
  using Point = typename GridBase<T>::Point;
  using GridBase<T>::nu;
  using GridBase<T>::nv;
  using GridBase<T>::nw;
  using GridBase<T>::unit_cell;
  using GridBase<T>::spacegroup;
  using GridBase<T>::data;

  /// @brief Spacing (in Angstroms) between consecutive grid planes.
  ///
  /// spacing[0] is distance between u planes, etc.
  /// Note: spacing is between planes, not between grid points.
  /// Computed as 1/(n*cell_length) for each axis.
  double spacing[3] = {0., 0., 0.};

  /// @brief Orthogonalization matrix scaled by grid dimensions.
  ///
  /// Each column of unit_cell.orth.mat divided by {nu, nv, nw}.
  /// Used for efficient conversion of fractional deltas to orthogonal.
  UpperTriangularMat33 orth_n;

  /// @brief Copy grid metadata (cell, space group, dimensions, axis order).
  ///
  /// Copies unit_cell, spacegroup, nu, nv, nw, axis_order from another GridMeta,
  /// and recalculates spacing and orth_n.
  /// @param g Source GridMeta
  void copy_metadata_from(const GridMeta& g) {
    unit_cell = g.unit_cell;
    spacegroup = g.spacegroup;
    nu = g.nu;
    nv = g.nv;
    nw = g.nw;
    this->axis_order = g.axis_order;
    calculate_spacing();
  }

  /// @brief Compute spacing and scaled orthogonalization matrix.
  ///
  /// Recalculates #spacing and #orth_n based on unit cell and grid dimensions.
  /// Must be called after changing unit_cell or grid dimensions.
  /// @throws Raises exception if unit cell is not in standard orientation
  void calculate_spacing() {
    spacing[0] = 1.0 / (nu * unit_cell.ar);
    spacing[1] = 1.0 / (nv * unit_cell.br);
    spacing[2] = 1.0 / (nw * unit_cell.cr);
    Vec3 inv_n(1.0 / nu, 1.0 / nv, 1.0 / nw);
    orth_n = unit_cell.orth.mat.multiply_by_diagonal(inv_n);
    if (!unit_cell.orth.mat.is_upper_triangular())
      fail("Grids work only with the standard orientation of crystal frame (SCALEn)");
  }

  /// @brief Set grid dimensions and recalculate spacing (no space group check).
  /// @param nu_ Dimension along first axis
  /// @param nv_ Dimension along second axis
  /// @param nw_ Dimension along third axis
  void set_size_without_checking(int nu_, int nv_, int nw_) {
    GridBase<T>::set_size_without_checking(nu_, nv_, nw_);
    calculate_spacing();
    this->axis_order = AxisOrder::XYZ;
  }

  /// @brief Set grid dimensions with space group compatibility check.
  /// @param nu_ Dimension along first axis
  /// @param nv_ Dimension along second axis
  /// @param nw_ Dimension along third axis
  /// @throws Raises exception if dimensions incompatible with space group
  void set_size(int nu_, int nv_, int nw_) {
    check_grid_factors(spacegroup, {{nu_, nv_, nw_}});
    set_size_without_checking(nu_, nv_, nw_);
  }

  /// @brief Calculate grid dimensions from desired spacing.
  ///
  /// Chooses dimensions with small prime factors (2, 3, 5) compatible with space group.
  /// @param approx_spacing Target spacing in Angstroms
  /// @param rounding Strategy for choosing nearby dimensions
  void set_size_from_spacing(double approx_spacing, GridSizeRounding rounding) {
    std::array<double, 3> limit = {{unit_cell.a / approx_spacing,
                                    unit_cell.b / approx_spacing,
                                    unit_cell.c / approx_spacing}};
    auto m = good_grid_size(limit, rounding, spacegroup);
    set_size_without_checking(m[0], m[1], m[2]);
  }

  /// @brief Set unit cell parameters from individual values.
  /// @param a Cell length (Angstroms)
  /// @param b Cell length (Angstroms)
  /// @param c Cell length (Angstroms)
  /// @param alpha Angle (degrees)
  /// @param beta Angle (degrees)
  /// @param gamma Angle (degrees)
  void set_unit_cell(double a, double b, double c,
                     double alpha, double beta, double gamma) {
    unit_cell.set(a, b, c, alpha, beta, gamma);
    calculate_spacing();
  }

  /// @brief Set unit cell.
  /// @param cell Unit cell to assign
  void set_unit_cell(const UnitCell& cell) {
    unit_cell = cell;
    calculate_spacing();
  }

  /// @brief Initialize grid from a structure (typically Model/Chain/Residue).
  ///
  /// Extracts space group and unit cell. If approx_spacing > 0,
  /// sets grid dimensions based on spacing.
  /// @tparam S Structure type with find_spacegroup() and cell members
  /// @param st Structure
  /// @param approx_spacing Target grid spacing in Angstroms (default: 0, no sizing)
  template<typename S>
  void setup_from(const S& st, double approx_spacing=0) {
    spacegroup = st.find_spacegroup();
    unit_cell = st.cell;
    if (approx_spacing > 0)
      set_size_from_spacing(approx_spacing, GridSizeRounding::Up);
  }

  /// @brief Get index in data array with periodic wrapping.
  ///
  /// Safe but slower than index_q(). Applies modulo to all indices.
  /// @param u Grid index (will be wrapped)
  /// @param v Grid index (will be wrapped)
  /// @param w Grid index (will be wrapped)
  /// @return Index into data array
  size_t index_s(int u, int v, int w) const {
    this->check_not_empty();
    return this->index_q(modulo(u, nu), modulo(v, nv), modulo(w, nw));
  }

  /// @brief Get value at grid point with periodic wrapping.
  /// @param u Grid index
  /// @param v Grid index
  /// @param w Grid index
  /// @return Grid value at the (normalized) indices
  T get_value(int u, int v, int w) const {
    return data[index_s(u, v, w)];
  }

  /// @brief Set value at grid point with periodic wrapping.
  /// @param u Grid index
  /// @param v Grid index
  /// @param w Grid index
  /// @param x Value to assign
  void set_value(int u, int v, int w, T x) {
    data[index_s(u, v, w)] = x;
  }

  /// @brief Get a Point at given grid indices with periodic wrapping.
  ///
  /// The returned Point has normalized indices u, v, w in [0, nu), [0, nv), [0, nw).
  /// @param u Grid index
  /// @param v Grid index
  /// @param w Grid index
  /// @return Point with normalized indices
  Point get_point(int u, int v, int w) {
    u = modulo(u, nu);
    v = modulo(v, nv);
    w = modulo(w, nw);
    return {u, v, w, &data[this->index_q(u, v, w)]};
  }

  /// @brief Get the grid point nearest to a fractional coordinate.
  /// @param f Fractional coordinates
  /// @return Point at nearest grid position
  /// @throws Raises exception if grid is not in XYZ order
  Point get_nearest_point(const Fractional& f) {
    if (this->axis_order != AxisOrder::XYZ)
      fail("grid is not fully setup");
    return get_point(iround(f.x * nu), iround(f.y * nv), iround(f.z * nw));
  }

  /// @brief Get the grid point nearest to an orthogonal (Cartesian) position.
  /// @param pos Orthogonal coordinates (Angstroms)
  /// @return Point at nearest grid position
  Point get_nearest_point(const Position& pos) {
    return get_nearest_point(unit_cell.fractionalize(pos));
  }

  /// @brief Get the index of the nearest grid point to a fractional coordinate.
  /// @param f Fractional coordinates
  /// @return Index into data array
  size_t get_nearest_index(const Fractional& f) {
    return index_s(iround(f.x * nu), iround(f.y * nv), iround(f.z * nw));
  }

  /// @brief Convert a grid Point to fractional coordinates.
  ///
  /// The Point's indices are normalized, so coordinates are in [0, 1).
  /// @param p Point with normalized indices
  /// @return Fractional coordinates
  Fractional point_to_fractional(const Point& p) const {
    return this->get_fractional(p.u, p.v, p.w);
  }

  /// @brief Convert a grid Point to orthogonal coordinates.
  /// @param p Point with normalized indices
  /// @return Orthogonal position (Angstroms)
  Position point_to_position(const Point& p) const {
    return this->get_position(p.u, p.v, p.w);
  }

  /// @brief Helper to split a real coordinate into integer and fractional parts.
  /// @param x Real coordinate
  /// @param n Grid dimension
  /// @param iptr Output: normalized integer part in [0, n)
  /// @return Fractional part in [0, 1)
  static double grid_modulo(double x, int n, int* iptr) {
    double f = std::floor(x);
    *iptr = modulo((int)f, n);
    return x - f;
  }

  /// @brief Trilinear interpolation at a grid coordinate.
  ///
  /// Reference: https://en.wikipedia.org/wiki/Trilinear_interpolation
  /// @param x Grid coordinate (x=1.5 is between 2nd and 3rd grid point). Wraps periodically.
  /// @param y Grid coordinate
  /// @param z Grid coordinate
  /// @return Interpolated value using trilinear basis functions
  T trilinear_interpolation(double x, double y, double z) const {
    this->check_not_empty();
    int u, v, w;
    double xd = grid_modulo(x, nu, &u);
    double yd = grid_modulo(y, nv, &v);
    double zd = grid_modulo(z, nw, &w);
    assert(u >= 0 && v >= 0 && w >= 0);
    assert(u < nu && v < nv && w < nw);
    T avg[2];
    for (int i = 0; i < 2; ++i) {
      int wi = (i == 0 || w + 1 != nw ? w + i : 0);
      size_t idx1 = this->index_q(u, v, wi);
      int v2 = v + 1 != nv ? v + 1 : 0;
      size_t idx2 = this->index_q(u, v2, wi);
      int u_add = u + 1 != nu ? 1 : -u;
      avg[i] = (T) lerp_(lerp_(data[idx1], data[idx1 + u_add], xd),
                         lerp_(data[idx2], data[idx2 + u_add], xd),
                         yd);
    }
    return (T) lerp_(avg[0], avg[1], zd);
  }
  /// @brief Trilinear interpolation at fractional coordinates.
  /// @param fctr Fractional coordinates
  /// @return Interpolated value
  T trilinear_interpolation(const Fractional& fctr) const {
    return trilinear_interpolation(fctr.x * nu, fctr.y * nv, fctr.z * nw);
  }

  /// @brief Trilinear interpolation at orthogonal coordinates.
  /// @param ctr Orthogonal coordinates (Angstroms)
  /// @return Interpolated value
  T trilinear_interpolation(const Position& ctr) const {
    return trilinear_interpolation(unit_cell.fractionalize(ctr));
  }

  /// @brief Tricubic interpolation at a grid coordinate.
  /// @details Uses Catmull–Rom cubic splines applied as a tensor product in three dimensions.
  /// Smoother than trilinear but more expensive. See cubic_interpolation() for the 1D formula.
  /// @param x Grid coordinate (x=1.5 is between 2nd and 3rd grid point). Wraps periodically.
  /// @param y Grid coordinate
  /// @param z Grid coordinate
  /// @return Interpolated value (double precision)
  /// @par References
  /// Afonine, P.V., Poon, B.K., Read, R.J., Sobolev, O.V., Terwilliger, T.C.,
  /// Urzhumtsev, A. & Adams, P.D. (2018). Real-space refinement in PHENIX for
  /// cryo-EM and crystallography. Acta Cryst. D74, 531–544.
  /// https://doi.org/10.1107/S2059798318006551
  double tricubic_interpolation(double x, double y, double z) const {
    std::array<std::array<std::array<T,4>,4>,4> copy;
    copy_4x4x4(x, y, z, copy);
    auto s = [&copy](int i, int j, int k) { return copy[i][j][k]; };
    double a[4], b[4];
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j)
        a[j] = cubic_interpolation(z, s(i,j,0), s(i,j,1), s(i,j,2), s(i,j,3));
      b[i] = cubic_interpolation(y, a[0], a[1], a[2], a[3]);
    }
    return cubic_interpolation(x, b[0], b[1], b[2], b[3]);
  }
  /// @brief Tricubic interpolation at fractional coordinates.
  /// @param fctr Fractional coordinates
  /// @return Interpolated value
  double tricubic_interpolation(const Fractional& fctr) const {
    return tricubic_interpolation(fctr.x * nu, fctr.y * nv, fctr.z * nw);
  }

  /// @brief Tricubic interpolation at orthogonal coordinates.
  /// @param ctr Orthogonal coordinates (Angstroms)
  /// @return Interpolated value
  double tricubic_interpolation(const Position& ctr) const {
    return tricubic_interpolation(unit_cell.fractionalize(ctr));
  }

  /// @brief Tricubic interpolation with first derivatives.
  ///
  /// Returns the interpolated value and partial derivatives.
  /// @param x Grid coordinate
  /// @param y Grid coordinate
  /// @param z Grid coordinate
  /// @return Array {value, df/dx, df/dy, df/dz} in grid coordinates
  std::array<double,4> tricubic_interpolation_der(double x, double y, double z) const {
    std::array<std::array<std::array<T,4>,4>,4> copy;
    copy_4x4x4(x, y, z, copy);
    auto s = [&copy](int i, int j, int k) { return copy[i][j][k]; };
    double a[4][4];
    double b[4];
    for (int i = 0; i < 4; ++i)
      for (int j = 0; j < 4; ++j)
        a[i][j] = cubic_interpolation(z, s(i,j,0), s(i,j,1), s(i,j,2), s(i,j,3));
    for (int i = 0; i < 4; ++i)
      b[i] = cubic_interpolation(y, a[i][0], a[i][1], a[i][2], a[i][3]);
    std::array<double, 4> ret;
    ret[0] = cubic_interpolation(x, b[0], b[1], b[2], b[3]);
    ret[1] = cubic_interpolation_der(x, b[0], b[1], b[2], b[3]);
    for (int i = 0; i < 4; ++i)
      b[i] = cubic_interpolation(x, a[0][i], a[1][i], a[2][i], a[3][i]);
    ret[2] = cubic_interpolation_der(y, b[0], b[1], b[2], b[3]);
    for (int i = 0; i < 4; ++i)
      for (int j = 0; j < 4; ++j)
        a[i][j] = cubic_interpolation(y, s(i,0,j), s(i,1,j), s(i,2,j), s(i,3,j));
    for (int i = 0; i < 4; ++i)
      b[i] = cubic_interpolation(x, a[0][i], a[1][i], a[2][i], a[3][i]);
    ret[3] = cubic_interpolation_der(z, b[0], b[1], b[2], b[3]);
    return ret;
  }
  /// @brief Tricubic interpolation with derivatives at fractional coordinates.
  /// @param fctr Fractional coordinates
  /// @return Array {value, df/da, df/db, df/dc} in fractional coordinates
  std::array<double,4> tricubic_interpolation_der(const Fractional& fctr) const {
    auto r = tricubic_interpolation_der(fctr.x * nu, fctr.y * nv, fctr.z * nw);
    return {r[0], r[1] * nu, r[2] * nv, r[3] * nw};
  }

  /// @brief Helper: extract 4x4x4 block of grid values for tricubic interpolation.
  /// @private Internal use only. Modifies x, y, z to fractional parts.
  void copy_4x4x4(double& x, double& y, double& z,
                  std::array<std::array<std::array<T,4>,4>,4>& copy) const {
    this->check_not_empty();
    auto prepare_indices = [](double& r, int nt, int (&indices)[4]) {
      int t;
      r = grid_modulo(r, nt, &t);
      indices[0] = (t != 0 ? t : nt) - 1;
      indices[1] = t;
      if (t + 2 < nt) {
        indices[2] = t + 1;
        indices[3] = t + 2;
      } else {
        indices[2] = t + 2 == nt ? t + 1 : 0;
        indices[3] = t + 2 == nt ? 0 : 1;
      }
    };
    int u_indices[4], v_indices[4], w_indices[4];
    prepare_indices(x, nu, u_indices);
    prepare_indices(y, nv, v_indices);
    prepare_indices(z, nw, w_indices);
    for (int i = 0; i < 4; ++i)
      for (int j = 0; j < 4; ++j)
        for (int k = 0; k < 4; ++k)
          copy[i][j][k] = this->get_value_q(u_indices[i], v_indices[j], w_indices[k]);
  }

  /// @brief Interpolate value at fractional coordinates using specified method.
  /// @param f Fractional coordinates
  /// @param order Interpolation order: 0 (nearest), 1 (trilinear), 3 (tricubic)
  /// @return Interpolated value
  /// @throws std::invalid_argument if order is not 0, 1, or 3
  T interpolate_value(const Fractional& f, int order=1) const {
    switch (order) {
      case 0: return *const_cast<Grid<T>*>(this)->get_nearest_point(f).value;
      case 1: return trilinear_interpolation(f);
      case 3: return (T) tricubic_interpolation(f);
    }
    throw std::invalid_argument("interpolation \"order\" must 0, 1 or 3");
  }

  /// @brief Interpolate value at orthogonal coordinates using specified method.
  /// @param ctr Orthogonal coordinates (Angstroms)
  /// @param order Interpolation order: 0 (nearest), 1 (trilinear), 3 (tricubic)
  /// @return Interpolated value
  T interpolate_value(const Position& ctr, int order=1) const {
    return interpolate_value(unit_cell.fractionalize(ctr), order);
  }

  /// @brief Extract a rectangular subarray of grid points with periodic wrapping.
  ///
  /// Copies a contiguous block of grid values into a destination array.
  /// Handles wrapping across periodic boundaries.
  /// @param dest Destination array (at least shape[0]*shape[1]*shape[2] elements)
  /// @param start Starting grid indices {u, v, w}
  /// @param shape Block size {du, dv, dw}
  void get_subarray(T* dest, std::array<int,3> start, std::array<int,3> shape) const {
    this->check_not_empty();
    if (this->axis_order != AxisOrder::XYZ)
      fail("get_subarray() is for Grids in XYZ order");
    const int u_start0 = modulo(start[0], nu);
    for (int w = 0; w < shape[2]; w++) {
      const int w0 = modulo(start[2] + w, nw);
      for (int v = 0; v < shape[1]; v++) {
        const int v0 = modulo(start[1] + v, nv);
        int u_start = u_start0;
        const T* src0 = &data[this->index_q(u_start, v0, w0)];
        int len = shape[0];
        while (len > nu - u_start) {
          int elem = nu - u_start;
          std::copy(src0, src0 + elem, dest);
          src0 -= u_start;
          dest += elem;
          len -= elem;
          u_start = 0;
        }
        std::copy(src0, src0 + len, dest);
        dest += len;
      }
    }
  }

  /// @brief Set a rectangular subarray of grid points with periodic wrapping.
  ///
  /// Copies a block of values from a source array into the grid.
  /// Handles wrapping across periodic boundaries.
  /// @param src Source array (at least shape[0]*shape[1]*shape[2] elements)
  /// @param start Starting grid indices {u, v, w}
  /// @param shape Block size {du, dv, dw}
  void set_subarray(const T* src, std::array<int,3> start, std::array<int,3> shape) {
    this->check_not_empty();
    if (this->axis_order != AxisOrder::XYZ)
      fail("set_subarray() is for Grids in XYZ order");
    const int u_start0 = modulo(start[0], nu);
    for (int w = 0; w < shape[2]; w++) {
      const int w0 = modulo(start[2] + w, nw);
      for (int v = 0; v < shape[1]; v++) {
        const int v0 = modulo(start[1] + v, nv);
        int u_start = u_start0;
        T* dst0 = &data[this->index_q(u_start, v0, w0)];
        int len = shape[0];
        while (len > nu - u_start) {
          int elem = nu - u_start;
          std::copy(src, src + elem, dst0);
          dst0 -= u_start;
          src += elem;
          len -= elem;
          u_start = 0;
        }
        std::copy(src, src + len, dst0);
        src += len;
      }
    }
  }

  /// @brief Validate and adjust size parameters for box operations.
  /// @tparam UsePbc If true, apply periodic boundary conditions; otherwise clamp to grid
  /// @param du Half-size along first axis (may be adjusted)
  /// @param dv Half-size along second axis (may be adjusted)
  /// @param dw Half-size along third axis (may be adjusted)
  /// @param fail_on_too_large_radius If true, raise exception if radius too large for PBC
  template <bool UsePbc>
  void check_size_for_points_in_box(int& du, int& dv, int& dw,
                                    bool fail_on_too_large_radius) const {
    if (UsePbc) {
      if (fail_on_too_large_radius) {
        if (2 * du >= nu || 2 * dv >= nv || 2 * dw >= nw)
          fail("grid operation failed: radius bigger than half the unit cell?");
      } else {
        // If we'd use the minimum image convention the max would be (nu-1)/2.
        // The limits set here are necessary for index_n() that is used below.
        du = std::min(du, nu - 1);
        dv = std::min(dv, nv - 1);
        dw = std::min(dw, nw - 1);
      }
    }
  }

  /// @brief Internal: iterate over grid points in a box around a fractional coordinate.
  /// @tparam UsePbc If true, apply periodic boundary conditions
  /// @tparam Func Callable(T&, double, Position, int, int, int) invoked for each point
  /// @param fctr Fractional center coordinate
  /// @param du Half-extent along first axis (in grid points)
  /// @param dv Half-extent along second axis (in grid points)
  /// @param dw Half-extent along third axis (in grid points)
  /// @param func Callback function(value_ref, distance_sq, delta_position, u, v, w)
  /// @param radius Optional spherical radius limit (INFINITY for box only)
  template <bool UsePbc, typename Func>
  void do_use_points_in_box(const Fractional& fctr, int du, int dv, int dw, Func&& func,
                            double radius=INFINITY) {
    double max_dist_sq = radius * radius;
    const Fractional nctr(fctr.x * nu, fctr.y * nv, fctr.z * nw);
    int u0 = iround(nctr.x);
    int v0 = iround(nctr.y);
    int w0 = iround(nctr.z);
    int u_lo = u0 - du;
    int u_hi = u0 + du;
    int v_lo = v0 - dv;
    int v_hi = v0 + dv;
    int w_lo = w0 - dw;
    int w_hi = w0 + dw;
    if (!UsePbc) {
      u_lo = std::max(u_lo, 0);
      u_hi = std::min(u_hi, nu - 1);
      v_lo = std::max(v_lo, 0);
      v_hi = std::min(v_hi, nv - 1);
      w_lo = std::max(w_lo, 0);
      w_hi = std::min(w_hi, nw - 1);
    }
    int u_0 = UsePbc ? modulo(u_lo, nu) : u_lo;
    int v_0 = UsePbc ? modulo(v_lo, nv) : v_lo;
    int w_0 = UsePbc ? modulo(w_lo, nw) : w_lo;
    auto wrap = [](int& q, int nq) { if (UsePbc && q == nq) q = 0; };
    Fractional fdelta(nctr.x - u_lo, 0, 0);
    for (int w = w_lo, w_ = w_0; w <= w_hi; ++w, wrap(++w_, nw)) {
      fdelta.z = nctr.z - w;
      for (int v = v_lo, v_ = v_0; v <= v_hi; ++v, wrap(++v_, nv)) {
        fdelta.y = nctr.y - v;
        Position delta(orth_n.multiply(fdelta));
        T* t = &data[this->index_q(u_0, v_, w_)];
        double dist_sq0 = sq(delta.y) + sq(delta.z);
        if (dist_sq0 > max_dist_sq)
          continue;
        for (int u = u_lo, u_ = u_0;;) {
          double dist_sq = dist_sq0 + sq(delta.x);
          if (!(dist_sq > max_dist_sq))
            func(*t, dist_sq, delta, u, v, w);
          if (u >= u_hi)
            break;
          ++u;
          ++u_;
          ++t;
          if (UsePbc && u_ == nu) {
            u_ = 0;
            t -= nu;
          }
          delta.x -= orth_n.a11;
        }
      }
    }
  }

  /// @brief Iterate over grid points in a box around a fractional coordinate.
  /// @tparam UsePbc If true, apply periodic boundary conditions
  /// @tparam Func Callable(T&, double, Position, int, int, int) invoked for each point
  /// @param fctr Fractional center coordinate
  /// @param du Half-extent along first axis (in grid points)
  /// @param dv Half-extent along second axis (in grid points)
  /// @param dw Half-extent along third axis (in grid points)
  /// @param func Callback function(value_ref, distance_sq, delta_position, u, v, w)
  /// @param fail_on_too_large_radius If true and UsePbc, raise exception for oversized box
  /// @param radius Optional spherical radius limit (INFINITY for box only)
  template <bool UsePbc, typename Func>
  void use_points_in_box(const Fractional& fctr, int du, int dv, int dw,
                         Func&& func, bool fail_on_too_large_radius=true,
                         double radius=INFINITY) {
    check_size_for_points_in_box<UsePbc>(du, dv, dw, fail_on_too_large_radius);
    do_use_points_in_box<UsePbc>(fctr, du, dv, dw, func, radius);
  }

  /// @brief Iterate over grid points within a spherical radius of a fractional coordinate.
  /// @tparam UsePbc If true, apply periodic boundary conditions
  /// @tparam Func Callable(T&, double) invoked for each point
  /// @param fctr Fractional center coordinate
  /// @param radius Spherical radius (in Angstroms)
  /// @param func Callback function(value_ref, distance_sq)
  /// @param fail_on_too_large_radius If true and UsePbc, raise exception for large radius
  template <bool UsePbc, typename Func>
  void use_points_around(const Fractional& fctr, double radius, Func&& func,
                         bool fail_on_too_large_radius=true) {
    int du = (int) std::ceil(radius / spacing[0]);
    int dv = (int) std::ceil(radius / spacing[1]);
    int dw = (int) std::ceil(radius / spacing[2]);
    use_points_in_box<UsePbc>(
        fctr, du, dv, dw,
        [&](T& ref, double d2, const Position&, int, int, int) { func(ref, d2); },
        fail_on_too_large_radius,
        radius);
  }

  /// @brief Set all grid points within a spherical radius to a constant value.
  /// @param ctr Orthogonal center (Angstroms)
  /// @param radius Spherical radius (Angstroms)
  /// @param value Value to assign
  /// @param use_pbc If true, apply periodic boundary conditions
  void set_points_around(const Position& ctr, double radius, T value, bool use_pbc=true) {
    Fractional fctr = unit_cell.fractionalize(ctr);
    if (use_pbc)
      use_points_around<true>(fctr, radius, [&](T& ref, double) { ref = value; }, false);
    else
      use_points_around<false>(fctr, radius, [&](T& ref, double) { ref = value; }, false);
  }

  /// @brief Replace all occurrences of one value with another.
  /// @param old_value Value to search for
  /// @param new_value Replacement value
  void change_values(T old_value, T new_value) {
    for (auto& d : data)
      if (impl::is_same(d, old_value))
        d = new_value;
  }

  /// @brief Apply a reduction function across all symmetry mates of each point.
  ///
  /// For each unique point under the space group, applies @p func to combine
  /// the values of all symmetry-related points, then assigns the result back
  /// to all mate positions.
  /// @tparam Func Binary function(T, T) → T
  /// @param func Reduction function, e.g., std::plus, std::max, etc.
  template<typename Func>
  void symmetrize(Func func) {
    symmetrize_using_ops(this->get_scaled_ops_except_id(), func);
  }

  /// @brief Apply a reduction function using an explicit list of operations.
  /// @tparam Func Binary function(T, T) → T
  /// @param ops GridOp operations (typically from get_scaled_ops_except_id())
  /// @param func Reduction function
  template<typename Func>
  void symmetrize_using_ops(const std::vector<GridOp>& ops, Func func) {
    if (ops.empty())
      return;
    std::vector<size_t> mates(ops.size(), 0);
    std::vector<signed char> visited(data.size(), 0);  // faster than vector<bool>
    size_t idx = 0;
    for (int w = 0; w != nw; ++w)
      for (int v = 0; v != nv; ++v)
        for (int u = 0; u != nu; ++u, ++idx) {
          assert(idx == this->index_q(u, v, w));
          if (visited[idx])
            continue;
          for (size_t k = 0; k < ops.size(); ++k) {
            std::array<int,3> t = ops[k].apply(u, v, w);
            mates[k] = this->index_n(t[0], t[1], t[2]);
          }
          T value = data[idx];
          for (size_t k : mates) {
            if (visited[k])
              fail("grid size is not compatible with space group");
            value = func(value, data[k]);
          }
          data[idx] = value;
          visited[idx] = 1;
          for (size_t k : mates) {
            data[k] = value;
            visited[k] = 1;
          }
        }
    assert(idx == data.size());
  }

  /// @brief Apply symmetry by taking the minimum value among symmetry mates.
  void symmetrize_min() {
    symmetrize([](T a, T b) { return (a < b || !(b == b)) ? a : b; });
  }

  /// @brief Apply symmetry by taking the maximum value among symmetry mates.
  void symmetrize_max() {
    symmetrize([](T a, T b) { return (a > b || !(b == b)) ? a : b; });
  }

  /// @brief Apply symmetry by taking the maximum absolute value among symmetry mates.
  void symmetrize_abs_max() {
    symmetrize([](T a, T b) { return (std::abs(a) > std::abs(b) || !(b == b)) ? a : b; });
  }

  /// @brief Apply symmetry by summing values of symmetry mates.
  ///
  /// Points on special positions (with fewer mates) contribute their value
  /// multiple times. Used for density map averaging without normalization.
  void symmetrize_sum() {
    symmetrize([](T a, T b) { return a + b; });
  }

  /// @brief Apply symmetry by selecting non-default values among mates.
  ///
  /// If a point's value equals @p default_, uses the value from a symmetry mate.
  /// @param default_ Value to replace
  void symmetrize_nondefault(T default_) {
    symmetrize([default_](T a, T b) { return impl::is_same(a, default_) ? b : a; });
  }

  /// @brief Apply symmetry by averaging values of symmetry mates.
  ///
  /// Sums symmetry mates and divides by space group order.
  void symmetrize_avg() {
    symmetrize_sum();
    if (spacegroup && spacegroup->number != 1) {
      int n_ops = spacegroup->operations().order();
      for (T& x : data)
        x /= n_ops;
    }
  }

  /// @brief Normalize grid values to zero mean and unit RMS.
  ///
  /// Subtracts the mean and scales by RMS, making statistics zero mean and unit variance.
  /// Does not work for complex-valued grids.
  void normalize() {
    DataStats stats = calculate_data_statistics(data);
    for (T& x : data)
      x = static_cast<T>((x - stats.dmean) / stats.rms);
  }
};

/// @brief Interpolate grid values from source to destination under a transformation.
///
/// For each point in the destination grid, applies the transformation and
/// interpolates the source grid value at that location.
/// TODO: add argument Box<Fractional> src_extent
/// See: interpolate_grid_around_model() in solmask.hpp
/// See: interpolate_values in python/grid.cpp
/// @tparam T Grid value type
/// @param dest Destination grid
/// @param src Source grid
/// @param tr Spatial transformation (rotation + translation)
/// @param order Interpolation order: 0 (nearest), 1 (trilinear), 3 (tricubic)
template<typename T>
void interpolate_grid(Grid<T>& dest, const Grid<T>& src, const Transform& tr, int order=1) {
  FTransform frac_tr = src.unit_cell.frac.combine(tr).combine(dest.unit_cell.orth);
  size_t idx = 0;
  for (int w = 0; w != dest.nw; ++w)
    for (int v = 0; v != dest.nv; ++v)
      for (int u = 0; u != dest.nu; ++u, ++idx) {
        Fractional dest_fr = dest.get_fractional(u, v, w);
        Fractional src_fr = frac_tr.apply(dest_fr);
        dest.data[idx] = src.interpolate_value(src_fr, order);
      }
}

/// @brief Calculate correlation coefficient between two grids.
///
/// Computes Pearson correlation between grid values, skipping NaN values.
/// @tparam T Grid value type
/// @param a First grid
/// @param b Second grid
/// @return Correlation object with mean, stddev, and correlation coefficient
/// @throws Raises exception if grids have different dimensions
template<typename T>
Correlation calculate_correlation(const GridBase<T>& a, const GridBase<T>& b) {
  if (a.data.size() != b.data.size() || a.nu != b.nu || a.nv != b.nv || a.nw != b.nw)
    fail("calculate_correlation(): grids have different sizes");
  Correlation corr;
  for (size_t i = 0; i != a.data.size(); ++i)
    if (!std::isnan(a.data[i]) && !std::isnan(b.data[i]))
      corr.add_point(a.data[i], b.data[i]);
  return corr;
}

} // namespace gemmi
#endif

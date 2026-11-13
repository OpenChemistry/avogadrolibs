// Copyright 2017-2019 Global Phasing Ltd.
//
// Crystallographic Symmetry. Space Groups. Coordinate Triplets.
//
// If this is all that you need from Gemmi you can just copy this file,
// src/symmetry.cpp fail.hpp and LICENSE.txt to your project.

/// @file
/// @brief Crystallographic symmetry operations, space groups, and reciprocal-space ASU.
///
/// This header provides core crystallographic symmetry data structures for macromolecular
/// crystallography: symmetry operations (Op), groups of operations (GroupOps), space groups
/// (SpaceGroup), and reciprocal-space asymmetric units (ReciprocalAsu). It also provides
/// functions for parsing, converting, and querying these structures.

#ifndef GEMMI_SYMMETRY_HPP_
#define GEMMI_SYMMETRY_HPP_

#include <cstdlib>    // for strtol, abs
#include <array>
#include <algorithm>  // for sort, remove
#include <functional> // for hash
#include <stdexcept>  // for invalid_argument
#include <string>
#include <tuple>      // for tie
#include <vector>

#include "fail.hpp"   // for fail, unreachable

namespace gemmi {

// OP

/// @brief A crystallographic symmetry operation or change-of-basis transformation.
///
/// Encodes both a fractional rotation matrix and a fractional translation vector.
/// Both are stored with a common denominator DEN=24 to handle fractions like 1/8
/// that appear in change-of-basis operations and advanced symmetry settings.
///
/// The encoding is: each matrix element m[i][j] and translation t[i] represents
/// the rational number (element / DEN). For example, an element value of 24 represents
/// 1.0, a value of 12 represents 0.5, and so on.
///
/// Real-space operations apply as: x' = (rot * x + tran) / DEN.
/// Reciprocal-space (Miller index) operations apply as: h' = rot^T * h / DEN
/// (note the transpose of the rotation matrix).
///
/// The notation field ('x' for real space, 'h' for reciprocal space, or ' ' for generic)
/// distinguishes between coordinate transformations and Miller index transformations.
struct GEMMI_DLL Op {
  /// @brief Denominator for rational fraction encoding. Set to 24 to handle 1/8.
  static constexpr int DEN = 24;
  typedef std::array<std::array<int, 3>, 3> Rot;
  typedef std::array<int, 3> Tran;

  /// @brief 3x3 rotation matrix with elements encoded as integers (divide by DEN for the actual value).
  Rot rot;
  /// @brief 3D translation vector with elements encoded as integers (divide by DEN for the actual value).
  Tran tran;
  /// @brief Space notation: 'x' for real-space (xyz), 'h' for reciprocal-space (hkl), ' ' for generic.
  char notation = ' ';

  /// @brief Check if this operation is in reciprocal space (hkl).
  /// @return true if notation == 'h', false otherwise
  bool is_hkl() const { return notation == 'h'; }

  /// @brief Return a copy of this operation with reciprocal-space (hkl) notation, clearing the translation.
  Op as_hkl() const {
    return is_hkl() ? *this : Op{rot, {0,0,0}, 'h'};
  }
  /// @brief Return a copy of this operation with real-space (xyz) notation, clearing the translation.
  Op as_xyz() const {
    return is_hkl() ? Op{rot, {0,0,0}, 'x'} : *this;
  }

  /// @brief Generate a string representation of this operation in crystallographic triplet notation (e.g., "x,y,z").
  /// @param style Style character (optional) for output formatting
  /// @return A string such as "x+1/2,y,z" or "-h,-k,l"
  std::string triplet(char style=' ') const;

  /// @brief Compute the inverse of this symmetry operation.
  /// @return A new Op representing the inverse transformation
  /// @throw std::runtime_error if the rotation matrix is singular
  Op inverse() const;

  /// @brief Wrap translation components into the range [0, DEN).
  /// @return A translation vector with elements in [0, DEN), representing coordinates in [0, 1).
  Op::Tran wrapped_tran() const {
    Op::Tran t = tran;
    for (int i = 0; i != 3; ++i) {
      if (t[i] >= DEN) // elements need to be in [0,DEN)
        t[i] %= DEN;
      else if (t[i] < 0)
        t[i] = ((t[i] + 1) % DEN) + DEN - 1;
    }
    return t;
  }

  /// @brief Normalize the translation to the range [0, DEN) (unit cell).
  /// @return Reference to this operation for chaining
  Op& wrap() {
    tran = wrapped_tran();
    return *this;
  }

  /// @brief Add a translation vector to this operation's translation component.
  /// @param a Translation vector to add
  /// @return Reference to this operation for chaining
  Op& translate(const Tran& a) {
    for (int i = 0; i != 3; ++i)
      tran[i] += a[i];
    return *this;
  }

  /// @brief Return a new operation with the given translation added.
  /// @param a Translation vector to add
  /// @return A new Op with modified translation
  Op translated(const Tran& a) const { return Op(*this).translate(a); }

  /// @brief Add a centering vector and normalize to unit cell.
  /// @param a Centering vector to add
  /// @return A new Op with translation added and wrapped to [0, DEN)
  Op add_centering(const Tran& a) const { return translated(a).wrap(); }

  /// @brief Return the negation of the rotation matrix (inversion).
  /// @return A 3x3 matrix with all elements negated
  Rot negated_rot() const {
    return {{{-rot[0][0], -rot[0][1], -rot[0][2]},
             {-rot[1][0], -rot[1][1], -rot[1][2]},
             {-rot[2][0], -rot[2][1], -rot[2][2]}}};
  }

  /// @brief Compute the transpose of a rotation matrix.
  /// @param rot Input rotation matrix
  /// @return Transposed matrix
  static Rot transpose(const Rot& rot) {
    return {{{rot[0][0], rot[1][0], rot[2][0]},
             {rot[0][1], rot[1][1], rot[2][1]},
             {rot[0][2], rot[1][2], rot[2][2]}}};
  }
  /// @brief Return the transpose of this operation's rotation matrix.
  /// @return Transposed rotation matrix
  Rot transposed_rot() const { return transpose(rot); }

  /// @brief Compute the determinant of the rotation matrix.
  /// @return DEN^3 (=13824) for proper rotations, -DEN^3 for rotoinversions, or 0 if singular
  int det_rot() const {
    return rot[0][0] * (rot[1][1] * rot[2][2] - rot[1][2] * rot[2][1])
         - rot[0][1] * (rot[1][0] * rot[2][2] - rot[1][2] * rot[2][0])
         + rot[0][2] * (rot[1][0] * rot[2][1] - rot[1][1] * rot[2][0]);
  }

  /// @brief Determine the rotation type (identity, 2-fold, 3-fold, etc.).
  /// @return Rotation type code (0 = none, 1 = 1-fold identity, 2 = 2-fold, 3 = 3-fold,
  ///         4 = 4-fold, 6 = 6-fold, -N for rotoinversion).
  /// @par References
  /// Grosse-Kunstleve, R.W. (1999). Algorithms for deriving crystallographic
  /// space-group information. Acta Cryst. A55, 383–395.
  /// https://doi.org/10.1107/S0108767398010186
  int rot_type() const {
    int det = det_rot();
    int tr_den = rot[0][0] + rot[1][1] + rot[2][2];
    int tr = tr_den / DEN;
    const int table[] = {0, 0, 2, 3, 4, 6, 1};
    if (std::abs(det) == DEN * DEN * DEN && tr * DEN == tr_den && std::abs(tr) <= 3)
      return det > 0 ? table[3 + tr] : -table[3 - tr];
    return 0;
  }

  /// @brief Combine two symmetry operations: result = this * b (first apply b, then apply this).
  /// @param b The second operation to apply
  /// @return New operation representing the combined transformation
  /// @note Does NOT wrap the translation to [0, DEN). Call wrap() on result if needed.
  Op combine(const Op& b) const {
    if (is_hkl() != b.is_hkl())
      fail("can't combine real- and reciprocal-space Op");
    Op r;
    for (int i = 0; i != 3; ++i) {
      r.tran[i] = tran[i] * Op::DEN;
      for (int j = 0; j != 3; ++j) {
        r.rot[i][j] = (rot[i][0] * b.rot[0][j] +
                       rot[i][1] * b.rot[1][j] +
                       rot[i][2] * b.rot[2][j]) / Op::DEN;
        r.tran[i] += rot[i][j] * b.tran[j];
      }
      r.tran[i] /= Op::DEN;
    }
    r.notation = notation;
    return r;
  }

  /// @brief Apply this real-space operation to a Cartesian coordinate.
  /// @param xyz Coordinate vector [x, y, z]
  /// @return Transformed coordinate (rot * xyz + tran) / DEN
  /// @throw std::runtime_error if this operation is in reciprocal space (is_hkl() == true)
  std::array<double, 3> apply_to_xyz(const std::array<double, 3>& xyz) const {
    if (is_hkl())
      fail("can't apply reciprocal-space Op to xyz");
    std::array<double, 3> out;
    for (int i = 0; i != 3; ++i)
      out[i] = (rot[i][0] * xyz[0] + rot[i][1] * xyz[1] + rot[i][2] * xyz[2] +
                tran[i]) / Op::DEN;
    return out;
  }

  /// @brief Type alias for Miller indices (hkl).
  // Miller is defined in the same way in namespace gemmi in unitcell.hpp
  using Miller = std::array<int, 3>;

  /// @brief Apply rotation to Miller indices without dividing by DEN.
  /// @param hkl Miller indices
  /// @return rot^T * hkl (in units of DEN; divide by DEN for actual result)
  /// @note Applies the transpose of the rotation matrix (reciprocal-space convention)
  Miller apply_to_hkl_without_division(const Miller& hkl) const {
    Miller r;
    for (int i = 0; i != 3; ++i)
      r[i] = (rot[0][i] * hkl[0] + rot[1][i] * hkl[1] + rot[2][i] * hkl[2]);
    return r;
  }
  /// @brief Divide Miller indices by DEN (convert from encoded to actual values).
  /// @param hkl Miller indices encoded with denominator DEN
  /// @return hkl / DEN (integer division)
  static Miller divide_hkl_by_DEN(const Miller& hkl) {
    return {{ hkl[0] / DEN, hkl[1] / DEN, hkl[2] / DEN }};
  }
  /// @brief Apply this operation to Miller indices.
  /// @param hkl Miller indices [h, k, l]
  /// @return Transformed Miller indices rot^T * hkl / DEN
  Miller apply_to_hkl(const Miller& hkl) const {
    return divide_hkl_by_DEN(apply_to_hkl_without_division(hkl));
  }

  /// @brief Compute the phase shift caused by this operation's translation component.
  /// @param hkl Miller indices
  /// @return Phase shift in radians: -2π * (h*t_x + k*t_y + l*t_z) / DEN
  double phase_shift(const Miller& hkl) const {
    constexpr double mult = -2 * 3.1415926535897932384626433832795 / Op::DEN;
    return mult * (hkl[0] * tran[0] + hkl[1] * tran[1] + hkl[2] * tran[2]);
  }

  /// @brief Convert to a 4x4 integer Seitz matrix representation.
  /// @return 4x4 homogeneous transformation matrix (rotation|translation) / (0 0 0 | 1)
  std::array<std::array<int, 4>, 4> int_seitz() const {
    std::array<std::array<int, 4>, 4> t;
    for (int i = 0; i < 3; ++i)
      t[i] = { rot[i][0], rot[i][1], rot[i][2], tran[i] };
    t[3] = { 0, 0, 0, 1 };
    return t;
  }

  /// @brief Convert to a 4x4 double-precision Seitz matrix representation.
  /// @return 4x4 homogeneous transformation matrix with normalized (divided by DEN) elements
  std::array<std::array<double, 4>, 4> float_seitz() const {
    std::array<std::array<double, 4>, 4> t;
    double m = 1.0 / Op::DEN;
    for (int i = 0; i < 3; ++i)
      t[i] = { m * rot[i][0], m * rot[i][1], m * rot[i][2], m * tran[i] };
    t[3] = { 0., 0., 0., 1. };
    return t;
  }

  /// @brief Create an identity operation.
  /// @return Identity operation: rot=I, tran=0, notation=' '
  static constexpr Op identity() {
    return {{{{DEN,0,0}, {0,DEN,0}, {0,0,DEN}}}, {0,0,0}, ' '};
  }
  /// @brief Create an inversion (point reflection) rotation matrix.
  /// @return 3x3 matrix representing -I (negative identity)
  static constexpr Op::Rot inversion_rot() {
    return {{{-DEN,0,0}, {0,-DEN,0}, {0,0,-DEN}}};
  }
  /// @brief Less-than comparison operator for sorting.
  /// @param rhs Operation to compare to
  /// @return true if (rot, tran) lexicographically < (rhs.rot, rhs.tran)
  bool operator<(const Op& rhs) const {
    return std::tie(rot, tran) < std::tie(rhs.rot, rhs.tran);
  }
};

/// @brief Equality comparison for operations (notation is ignored).
inline bool operator==(const Op& a, const Op& b) {
  return a.rot == b.rot && a.tran == b.tran;
}
/// @brief Inequality comparison for operations.
inline bool operator!=(const Op& a, const Op& b) { return !(a == b); }

/// @brief Compose two symmetry operations: a * b applies b first, then a.
/// @param a First operation
/// @param b Second operation
/// @return New operation representing composition, with wrapped translation
inline Op operator*(const Op& a, const Op& b) { return a.combine(b).wrap(); }
/// @brief In-place composition operator.
/// @param a Operation to modify
/// @param b Operation to apply
/// @return Reference to modified a
inline Op& operator*=(Op& a, const Op& b) { a = a * b; return a; }

inline Op Op::inverse() const {
  int detr = det_rot();
  if (detr == 0)
    fail("cannot invert matrix: " + Op{rot, {0,0,0}, notation}.triplet());
  int d2 = Op::DEN * Op::DEN;
  Op inv;
  inv.rot[0][0] = d2 * (rot[1][1] * rot[2][2] - rot[2][1] * rot[1][2]) / detr;
  inv.rot[0][1] = d2 * (rot[0][2] * rot[2][1] - rot[0][1] * rot[2][2]) / detr;
  inv.rot[0][2] = d2 * (rot[0][1] * rot[1][2] - rot[0][2] * rot[1][1]) / detr;
  inv.rot[1][0] = d2 * (rot[1][2] * rot[2][0] - rot[1][0] * rot[2][2]) / detr;
  inv.rot[1][1] = d2 * (rot[0][0] * rot[2][2] - rot[0][2] * rot[2][0]) / detr;
  inv.rot[1][2] = d2 * (rot[1][0] * rot[0][2] - rot[0][0] * rot[1][2]) / detr;
  inv.rot[2][0] = d2 * (rot[1][0] * rot[2][1] - rot[2][0] * rot[1][1]) / detr;
  inv.rot[2][1] = d2 * (rot[2][0] * rot[0][1] - rot[0][0] * rot[2][1]) / detr;
  inv.rot[2][2] = d2 * (rot[0][0] * rot[1][1] - rot[1][0] * rot[0][1]) / detr;
  for (int i = 0; i != 3; ++i)
    inv.tran[i] = (-tran[0] * inv.rot[i][0]
                   -tran[1] * inv.rot[i][1]
                   -tran[2] * inv.rot[i][2]) / Op::DEN;
  inv.notation = notation;
  return inv;
}

/// @brief Convert a 4x4 Seitz matrix to an Op structure (inverse of Op::float_seitz()).
/// @param t 4x4 homogeneous transformation matrix
/// @return Equivalent Op with encoded rotation and translation (multiplied by DEN)
GEMMI_DLL Op seitz_to_op(const std::array<std::array<double,4>, 4>& t);

/// @brief Helper function to append a fractional value as a string.
/// @param s String to append to
/// @param w Encoded value (numerator * DEN / denominator)
GEMMI_DLL void append_op_fraction(std::string& s, int w);

/// @brief Parse one component of a crystallographic triplet (e.g., "x+1/2" from "x+1/2,y,z").
/// @param s String to parse
/// @param notation Output parameter: 'x' for real-space, 'h' for reciprocal-space
/// @param decimal_fract Optional output: decoded decimal fractional part
/// @return Array of 4 integers encoding [coeff_x, coeff_y, coeff_z, constant*DEN]
GEMMI_DLL std::array<int, 4> parse_triplet_part(const std::string& s, char& notation,
                                                double* decimal_fract=nullptr);
/// @brief Parse a crystallographic triplet string into an Op.
/// @param s Triplet string (e.g., "x+1/2,y,z" or "-h,-k,l")
/// @param notation Notation character: 'x' for real-space, 'h' for reciprocal-space, ' ' to auto-detect
/// @return Op representing the parsed transformation
GEMMI_DLL Op parse_triplet(const std::string& s, char notation=' ');

// GROUPS OF OPERATIONS

/// @brief Get centring (lattice) vectors for a given centring type.
/// @param centring_type Centring character: P, A, B, C, I, F, R, H, S, T
/// @return Vector of translation vectors (centering vectors). Corresponds to Table A1.4.2.2 in ITfC vol.B (edition 2010)
inline std::vector<Op::Tran> centring_vectors(char centring_type) {
  constexpr int h = Op::DEN / 2;
  constexpr int t = Op::DEN / 3;
  constexpr int d = 2 * t;
  // note: find_centering() depends on the order of operations in vector
  switch (centring_type & ~0x20) {
    case 'P': return {{0, 0, 0}};
    case 'A': return {{0, 0, 0}, {0, h, h}};
    case 'B': return {{0, 0, 0}, {h, 0, h}};
    case 'C': return {{0, 0, 0}, {h, h, 0}};
    case 'I': return {{0, 0, 0}, {h, h, h}};
    case 'R': return {{0, 0, 0}, {d, t, t}, {t, d, d}};
    // hall_symbols.html has no H, ITfC 2010 has no S and T
    case 'H': return {{0, 0, 0}, {d, t, 0}, {t, d, 0}};
    case 'S': return {{0, 0, 0}, {t, t, d}, {d, t, d}};
    case 'T': return {{0, 0, 0}, {t, d, t}, {d, t, d}};
    case 'F': return {{0, 0, 0}, {0, h, h}, {h, 0, h}, {h, h, 0}};
    default: fail("not a centring type: ", centring_type);
  }
}

/// @brief A crystallographic space group represented as generators and centring vectors.
///
/// GroupOps separates symmetry operations into two parts:
/// - sym_ops: primitive symmetry operations (generators or full group) in the conventional cell
/// - cen_ops: centring vectors (including the origin {0,0,0})
///
/// The complete set of symmetry operations is obtained by combining each sym_op with each cen_op.
/// The first sym_op is always the identity; the first cen_op is always {0,0,0}.
struct GroupOps {
  /// @brief Primitive symmetry operations (generators). sym_ops[0] is always identity.
  std::vector<Op> sym_ops;
  /// @brief Centring translation vectors. cen_ops[0] is always {0,0,0}.
  std::vector<Op::Tran> cen_ops;

  /// @brief Return the total number of symmetry operations (|sym_ops| * |cen_ops|).
  int order() const { return static_cast<int>(sym_ops.size()*cen_ops.size()); }

  /// @brief Generate all missing symmetry operations from the current generators using Dimino's algorithm.
  void add_missing_elements();
  /// @brief Second part of group generation algorithm (used internally and by twin.hpp).
  void add_missing_elements_part2(const std::vector<Op>& gen,
                                  size_t max_size, bool ignore_bad_gen);

  /// @brief Add inversion (point reflection) symmetry if not already present.
  /// @return true if inversion was added, false if it was already present
  bool add_inversion() {
    size_t init_size = sym_ops.size();
    sym_ops.reserve(2 * init_size);
    for (const Op& op : sym_ops) {
      Op::Rot neg = op.negated_rot();
      if (find_by_rotation(neg)) {
        sym_ops.resize(init_size);
        return false;
      }
      sym_ops.push_back({neg, op.tran, op.notation});
    }
    return true;
  }

  /// @brief Determine the Bravais lattice centring type from cen_ops.
  /// @return Character: 'P' (primitive), 'A'/'B'/'C' (base-centered), 'I' (body-centered),
  ///         'F' (face-centered), 'R'/'H'/'S'/'T' (rhombohedral variants), or 0 if unknown
  char find_centering() const {
    if (cen_ops.size() == 1 && cen_ops[0] == Op::Tran{0, 0, 0})
      return 'P';
    std::vector<Op::Tran> trans = cen_ops;
    std::sort(trans.begin(), trans.end());
    for (char c : {'A', 'B', 'C', 'I', 'F', 'R', 'H', 'S', 'T'}) {
      std::vector<Op::Tran> c_vectors = centring_vectors(c);
      if (c == 'R' || c == 'H') // these two are returned not sorted
        std::swap(c_vectors[1], c_vectors[2]);
      if (trans == c_vectors)
        return c;
    }
    return 0;
  }

  /// @brief Find a symmetry operation by its rotation matrix.
  /// @param r Rotation matrix to find
  /// @return Pointer to the operation if found, nullptr otherwise
  Op* find_by_rotation(const Op::Rot& r) {
    for (Op& op : sym_ops)
      if (op.rot == r)
        return &op;
    return nullptr;
  }

  /// @brief Find a symmetry operation by its rotation matrix (const version).
  /// @param r Rotation matrix to find
  /// @return Pointer to the operation if found, nullptr otherwise
  const Op* find_by_rotation(const Op::Rot& r) const {
    return const_cast<GroupOps*>(this)->find_by_rotation(r);
  }

  /// @brief Check if the space group is centrosymmetric (has an inversion center).
  /// @return true if inversion (-I rotation) is present in sym_ops
  bool is_centrosymmetric() const {
    return find_by_rotation(Op::inversion_rot()) != nullptr;
  }

  /// @brief Check if a reflection plane maps hkl to -hkl (Miller index centric condition).
  /// @param hkl Miller indices to check
  /// @return true if some operation maps hkl to -hkl
  bool is_reflection_centric(const Op::Miller& hkl) const {
    Op::Miller mhkl = {{-Op::DEN * hkl[0], -Op::DEN * hkl[1], -Op::DEN * hkl[2]}};
    for (const Op& op : sym_ops)
      if (op.apply_to_hkl_without_division(hkl) == mhkl)
        return true;
    return false;
  }

  /// @brief Count operations that map hkl to itself (without considering centring).
  /// @param hkl Miller indices
  /// @return Number of sym_ops that fix hkl (multiplicity factor)
  int epsilon_factor_without_centering(const Op::Miller& hkl) const {
    Op::Miller denh = {{Op::DEN * hkl[0], Op::DEN * hkl[1], Op::DEN * hkl[2]}};
    int epsilon = 0;
    for (const Op& op : sym_ops)
      if (op.apply_to_hkl_without_division(hkl) == denh)
        ++epsilon;
    return epsilon;
  }
  /// @brief Count all operations (including centring) that map hkl to itself.
  /// @param hkl Miller indices
  /// @return epsilon_factor_without_centering * |cen_ops|
  int epsilon_factor(const Op::Miller& hkl) const {
    return epsilon_factor_without_centering(hkl) * (int) cen_ops.size();
  }

  /// @brief Check if a centering translation causes a phase shift for the given hkl.
  /// @param c Centering translation vector
  /// @param hkl Miller indices
  /// @return true if (h*c_x + k*c_y + l*c_z) % DEN != 0
  static bool has_phase_shift(const Op::Tran& c, const Op::Miller& hkl) {
    return (hkl[0] * c[0] + hkl[1] * c[1] + hkl[2] * c[2]) % Op::DEN != 0;
  }

  /// @brief Check if a reflection is systematically absent due to centring or screw/glide.
  /// @param hkl Miller indices
  /// @return true if the reflection has a phase shift of π (destructive interference)
  bool is_systematically_absent(const Op::Miller& hkl) const {
    for (auto i = cen_ops.begin() + 1; i != cen_ops.end(); ++i)
      if (has_phase_shift(*i, hkl))
        return true;
    Op::Miller denh = {{Op::DEN * hkl[0], Op::DEN * hkl[1], Op::DEN * hkl[2]}};
    for (auto op = sym_ops.begin() + 1; op != sym_ops.end(); ++op)
      if (op->apply_to_hkl_without_division(hkl) == denh) {
        for (const Op::Tran& c : cen_ops)
          if (has_phase_shift({{op->tran[0] + c[0],
                                op->tran[1] + c[1],
                                op->tran[2] + c[2]}}, hkl))
            return true;
      }
    return false;
  }

  void change_basis_impl(const Op& cob, const Op& inv) {
    if (sym_ops.empty() || cen_ops.empty())
      return;

    // Apply change-of-basis to sym_ops.
    // Ignore the first item in sym_ops -- it's identity.
    for (auto op = sym_ops.begin() + 1; op != sym_ops.end(); ++op)
      *op = cob.combine(*op).combine(inv).wrap();

    // The number of centering vectors may be different.
    // As an ad-hoc method (not proved to be robust) add lattice points
    // from a super-cell.
    int idet = inv.det_rot() / (Op::DEN * Op::DEN * Op::DEN);
    if (idet > 1) {
      std::vector<Op::Tran> new_cen_ops;
      new_cen_ops.reserve(cen_ops.size() * idet * idet * idet);
      for (int i = 0; i < idet; ++i)
        for (int j = 0; j < idet; ++j)
          for (int k = 0; k < idet; ++k)
            for (Op::Tran& cen : cen_ops)
              new_cen_ops.push_back({i * Op::DEN + cen[0],
                                     j * Op::DEN + cen[1],
                                     k * Op::DEN + cen[2]});
      cen_ops.swap(new_cen_ops);
    }

    // Apply change-of-basis to centering vectors
    Op cvec = Op::identity();
    for (auto tr = cen_ops.begin() + 1; tr != cen_ops.end(); ++tr) {
      cvec.tran = *tr;
      *tr = cob.combine(cvec).combine(inv).wrap().tran;
    }

    // Remove redundant centering vectors.
    for (int i = static_cast<int>(cen_ops.size()) - 1; i > 0; --i)
      for (int j = i - 1; j >= 0; --j)
        if (cen_ops[i] == cen_ops[j]) {
          cen_ops.erase(cen_ops.begin() + i);
          break;
        }
  }

  /// @brief Apply a forward change-of-basis transformation (P_new = cob * P_old * cob^-1).
  /// @param cob Change-of-basis operation
  void change_basis_forward(const Op& cob) { change_basis_impl(cob, cob.inverse()); }
  /// @brief Apply a backward change-of-basis transformation.
  /// @param inv Inverse change-of-basis operation
  void change_basis_backward(const Op& inv) { change_basis_impl(inv.inverse(), inv); }

  /// @brief Get all symmetry operations sorted.
  /// @return Sorted vector combining all sym_ops with all cen_ops
  std::vector<Op> all_ops_sorted() const {
    std::vector<Op> ops;
    ops.reserve(sym_ops.size() * cen_ops.size());
    for (const Op& so : sym_ops)
      for (const Op::Tran& co : cen_ops)
        ops.push_back(so.add_centering(co));
    std::sort(ops.begin(), ops.end());
    return ops;
  }

  /// @brief Get the n-th symmetry operation (combining sym_ops and cen_ops).
  /// @param n Index (0-based)
  /// @return sym_ops[n % |sym_ops|] combined with cen_ops[n / |sym_ops|]
  Op get_op(int n) const {
    int n_cen = n / (int) sym_ops.size();
    int n_sym = n % (int) sym_ops.size();
    return sym_ops.at(n_sym).add_centering(cen_ops.at(n_cen));
  }

  /// @brief Check if two GroupOps represent the same group of operations.
  /// @param other Other GroupOps to compare
  /// @return true if all_ops_sorted() are identical
  bool is_same_as(const GroupOps& other) const {
    if (cen_ops.size() != other.cen_ops.size() ||
        sym_ops.size() != other.sym_ops.size())
      return false;
    return all_ops_sorted() == other.all_ops_sorted();
  }

  /// @brief Check if two GroupOps have the same centring vectors.
  /// @param other Other GroupOps to compare
  /// @return true if cen_ops are the same (ignoring order)
  bool has_same_centring(const GroupOps& other) const {
    if (cen_ops.size() != other.cen_ops.size())
      return false;
    if (std::is_sorted(cen_ops.begin(), cen_ops.end()) &&
        std::is_sorted(other.cen_ops.begin(), other.cen_ops.end()))
      return cen_ops == other.cen_ops;
    std::vector<Op::Tran> v1 = cen_ops;
    std::vector<Op::Tran> v2 = other.cen_ops;
    std::sort(v1.begin(), v1.end());
    std::sort(v2.begin(), v2.end());
    return v1 == v2;
  }

  /// @brief Check if two GroupOps have the same rotation parts (ignoring translations).
  /// @param other Other GroupOps to compare
  /// @return true if rotation matrices in sym_ops are the same (ignoring order)
  bool has_same_rotations(const GroupOps& other) const {
    if (sym_ops.size() != other.sym_ops.size())
      return false;
    auto sorted_rotations = [](const GroupOps& g) {
      std::vector<Op::Rot> r(g.sym_ops.size());
      for (size_t i = 0; i != r.size(); ++i)
        r[i] = g.sym_ops[i].rot;
      std::sort(r.begin(), r.end());
      return r;
    };
    return sorted_rotations(*this) == sorted_rotations(other);
  }

  /// @brief Compute minimal grid multiplicity in each direction for real-space sampling.
  /// @return Array [n_x, n_y, n_z] such that grid spacing <= 1/n in each direction
  /// @note Examples: {1,2,1} for P2_1, {1,1,6} for P6_1
  std::array<int, 3> find_grid_factors() const {
    const int T = Op::DEN;
    int r[3] = {T, T, T};
    for (Op op : *this)
      for (int i = 0; i != 3; ++i)
        if (op.tran[i] != 0 && op.tran[i] < r[i])
          r[i] = op.tran[i];
    return {T / r[0], T / r[1], T / r[2]};
  }

  /// @brief Check if two coordinate directions are related by some symmetry operation.
  /// @param u First direction (0=x, 1=y, 2=z)
  /// @param v Second direction (0=x, 1=y, 2=z)
  /// @return true if some operation maps direction u to direction v
  bool are_directions_symmetry_related(int u, int v) const {
    for (const Op& op : sym_ops)
      if (op.rot[u][v] != 0)
        return true;
    return false;
  }

  /// @brief Create a symmorphic space group by removing translations.
  /// @return New GroupOps with all translations set to zero
  GroupOps derive_symmorphic() const {
    GroupOps r(*this);
    for (Op& op : r.sym_ops)
      op.tran[0] = op.tran[1] = op.tran[2] = 0;
    return r;
  }

  /// @brief Forward iterator over all symmetry operations in this group.
  struct Iter {
    const GroupOps& gops;
    int n_sym, n_cen;
    /// @brief Increment iterator to next operation.
    void operator++() {
      if (++n_sym == (int) gops.sym_ops.size()) {
        ++n_cen;
        n_sym = 0;
      }
    }
    /// @brief Dereference iterator to get current operation.
    Op operator*() const {
      return gops.sym_ops.at(n_sym).translated(gops.cen_ops.at(n_cen)).wrap();
    }
    /// @brief Equality comparison for iterators.
    bool operator==(const Iter& other) const {
      return n_sym == other.n_sym && n_cen == other.n_cen;
    }
    /// @brief Inequality comparison for iterators.
    bool operator!=(const Iter& other) const { return !(*this == other); }
  };

  /// @brief Get iterator to the first symmetry operation.
  Iter begin() const { return {*this, 0, 0}; }
  /// @brief Get iterator to past-the-end position.
  Iter end() const { return {*this, 0, (int) cen_ops.size()}; }
};

inline void GroupOps::add_missing_elements() {
  // We always keep identity as sym_ops[0].
  if (sym_ops.empty() || sym_ops[0] != Op::identity())
    fail("oops");
  if (sym_ops.size() == 1)
    return;
  constexpr size_t max_size = 1024;
  // Below we assume that all centring vectors are already known (in cen_ops)
  // so when checking for a new element we compare only the 3x3 matrix.
  // Dimino's algorithm. https://physics.stackexchange.com/a/351400/95713
  std::vector<Op> gen(sym_ops.begin() + 1, sym_ops.end());
  sym_ops.resize(2);
  const Op::Rot idrot = Op::identity().rot;
  for (Op g = sym_ops[1] * sym_ops[1]; g.rot != idrot; g *= sym_ops[1]) {
    sym_ops.push_back(g);
    if (sym_ops.size() > max_size)
      fail("Too many elements in the group - bad generators");
  }
  // the rest is in separate function b/c it's reused in twin.hpp
  add_missing_elements_part2(gen, max_size, false);
}

inline void GroupOps::add_missing_elements_part2(const std::vector<Op>& gen,
                                                 size_t max_size, bool ignore_bad_gen) {
  for (size_t i = 1; i < gen.size(); ++i) {
    std::vector<Op> coset_repr(1, Op::identity());
    size_t init_size = sym_ops.size();
    for (;;) {
      size_t len = coset_repr.size();
      for (size_t j = 0; j != len; ++j) {
        for (size_t n = 0; n != i + 1; ++n) {
          Op sg = gen[n] * coset_repr[j];
          if (find_by_rotation(sg.rot) == nullptr) {
            sym_ops.push_back(sg);
            for (size_t k = 1; k != init_size; ++k)
              sym_ops.push_back(sg * sym_ops[k]);
            coset_repr.push_back(sg);
          }
        }
      }
      if (len == coset_repr.size())
        break;
      if (sym_ops.size() > max_size) {
        if (!ignore_bad_gen)
          fail("Too many elements in the group - bad generators");
        // ignore this generator and continue with the next one
        sym_ops.resize(init_size);
        break;
      }
    }
  }
}

// Create GroupOps from Ops by separating centering vectors
inline GroupOps split_centering_vectors(const std::vector<Op>& ops) {
  const Op identity = Op::identity();
  GroupOps go;
  go.sym_ops.push_back(identity);
  for (const Op& op : ops)
    if (Op* old_op = go.find_by_rotation(op.rot)) {
      Op::Tran tran = op.wrapped_tran();
      if (op.rot == identity.rot)  // pure shift
        go.cen_ops.push_back(tran);
      if (tran == identity.tran)  // or rather |tran| < |old_op->tran| ?
        old_op->tran = op.tran;
    } else {
      go.sym_ops.push_back(op);
    }
  return go;
}

/// @brief Generate symmetry operations from a Hall symbol string.
/// @param hall Hall symbol string (e.g., "P 1" or "P 2 2 21")
/// @return GroupOps with generators only (not the complete group)
GEMMI_DLL GroupOps generators_from_hall(const char* hall);

/// @brief Get the complete group of symmetry operations from a Hall symbol.
/// @param hall Hall symbol string
/// @return GroupOps with all elements generated from the Hall symbol
inline GroupOps symops_from_hall(const char* hall) {
  GroupOps ops = generators_from_hall(hall);
  ops.add_missing_elements();
  return ops;
}

// CRYSTAL SYSTEMS, POINT GROUPS AND LAUE CLASSES

/// @brief Crystal system classification (one of the seven Bravais lattice families).
enum class CrystalSystem : unsigned char {
  Triclinic=0, ///< Triclinic (lowest symmetry)
  Monoclinic,  ///< Monoclinic
  Orthorhombic, ///< Orthorhombic
  Tetragonal,  ///< Tetragonal
  Trigonal,    ///< Trigonal (rhombohedral in rhombohedral axes)
  Hexagonal,   ///< Hexagonal
  Cubic        ///< Cubic (highest symmetry)
};

/// @brief Convert crystal system enum to a string name.
/// @param system Crystal system to name
/// @return String: "triclinic", "monoclinic", "orthorhombic", etc.
inline const char* crystal_system_str(CrystalSystem system) {
  static const char* names[7] = {
    "triclinic", "monoclinic", "orthorhombic", "tetragonal",
    "trigonal", "hexagonal", "cubic"
  };
  return names[static_cast<int>(system)];
}

/// @brief Point group classification (32 crystallographic point groups).
enum class PointGroup : unsigned char {
  C1=0,   ///< 1 (identity only)
  Ci,     ///< -1 (inversion)
  C2,     ///< 2
  Cs,     ///< m
  C2h,    ///< 2/m
  D2,     ///< 222
  C2v,    ///< mm2
  D2h,    ///< mmm
  C4,     ///< 4
  S4,     ///< -4
  C4h,    ///< 4/m
  D4,     ///< 422
  C4v,    ///< 4mm
  D2d,    ///< -42m
  D4h,    ///< 4/mmm
  C3,     ///< 3
  C3i,    ///< -3
  D3,     ///< 32
  C3v,    ///< 3m
  D3d,    ///< -3m
  C6,     ///< 6
  C3h,    ///< -6
  C6h,    ///< 6/m
  D6,     ///< 622
  C6v,    ///< 6mm
  D3h,    ///< -62m
  D6h,    ///< 6/mmm
  T,      ///< 23
  Th,     ///< m-3
  O,      ///< 432
  Td,     ///< -43m
  Oh      ///< m-3m
};

/// @brief Convert point group enum to Hermann-Mauguin notation string.
/// @param pg Point group to name
/// @return String in Hermann-Mauguin notation (e.g., "mmm", "4/m")
inline const char* point_group_hm(PointGroup pg) {
  static const char hm_pointgroup_names[32][6] = {
    "1", "-1", "2", "m", "2/m", "222", "mm2", "mmm",
    "4", "-4", "4/m", "422", "4mm", "-42m", "4/mmm", "3",
    "-3", "32", "3m", "-3m", "6", "-6", "6/m", "622",
    "6mm", "-62m", "6/mmm", "23", "m-3", "432", "-43m", "m-3m",
  };
  return hm_pointgroup_names[static_cast<int>(pg)];
}

/// @brief Laue class (11 centrosymmetric point groups for diffraction).
/// @see http://reference.iucr.org/dictionary/Laue_class
enum class Laue : unsigned char {
  L1=0,   ///< 1 (triclinic)
  L2m,    ///< 2/m (monoclinic)
  Lmmm,   ///< mmm (orthorhombic)
  L4m,    ///< 4/m (tetragonal)
  L4mmm,  ///< 4/mmm (tetragonal)
  L3,     ///< -3 (trigonal)
  L3m,    ///< -3m (trigonal)
  L6m,    ///< 6/m (hexagonal)
  L6mmm,  ///< 6/mmm (hexagonal)
  Lm3,    ///< m-3 (cubic)
  Lm3m    ///< m-3m (cubic)
};

/// @brief Convert point group to its corresponding Laue class.
/// @param pg Point group
/// @return Associated Laue class
inline Laue pointgroup_to_laue(PointGroup pg) {
  static const Laue laue[32] = {
    Laue::L1, Laue::L1,
    Laue::L2m, Laue::L2m, Laue::L2m,
    Laue::Lmmm, Laue::Lmmm, Laue::Lmmm,
    Laue::L4m, Laue::L4m, Laue::L4m,
    Laue::L4mmm, Laue::L4mmm, Laue::L4mmm, Laue::L4mmm,
    Laue::L3, Laue::L3,
    Laue::L3m, Laue::L3m, Laue::L3m,
    Laue::L6m, Laue::L6m, Laue::L6m,
    Laue::L6mmm, Laue::L6mmm, Laue::L6mmm, Laue::L6mmm,
    Laue::Lm3, Laue::Lm3,
    Laue::Lm3m, Laue::Lm3m, Laue::Lm3m,
  };
  return laue[static_cast<int>(pg)];
}

/// @brief Get the centrosymmetric point group corresponding to a Laue class.
/// @param laue Laue class
/// @return Point group with inversion center
inline PointGroup laue_to_pointgroup(Laue laue) {
  static const PointGroup pg[11] = {
    PointGroup::Ci, PointGroup::C2h, PointGroup::D2h, PointGroup::C4h,
    PointGroup::D4h, PointGroup::C3i, PointGroup::D3d, PointGroup::C6h,
    PointGroup::D6h, PointGroup::Th, PointGroup::Oh
  };
  return pg[static_cast<int>(laue)];
}

/// @brief Get string representation of Laue class in Hermann-Mauguin notation.
/// @param laue Laue class
/// @return String representation
inline const char* laue_class_str(Laue laue) {
  return point_group_hm(laue_to_pointgroup(laue));
}

/// @brief Get the crystal system for a given Laue class.
/// @param laue Laue class
/// @return Crystal system classification
inline CrystalSystem crystal_system(Laue laue) {
  static const CrystalSystem crystal_systems[11] = {
    CrystalSystem::Triclinic,
    CrystalSystem::Monoclinic,
    CrystalSystem::Orthorhombic,
    CrystalSystem::Tetragonal, CrystalSystem::Tetragonal,
    CrystalSystem::Trigonal,   CrystalSystem::Trigonal,
    CrystalSystem::Hexagonal,  CrystalSystem::Hexagonal,
    CrystalSystem::Cubic,      CrystalSystem::Cubic
  };
  return crystal_systems[static_cast<int>(laue)];
}

/// @brief Get the crystal system for a given point group.
/// @param pg Point group
/// @return Crystal system classification
inline CrystalSystem crystal_system(PointGroup pg) {
  return crystal_system(pointgroup_to_laue(pg));
}

/// @brief Get point group and symmetry category flags for a space group number.
/// @param space_group_number Space group number (1-230)
/// @return Low 5 bits: point group index; bits 5-7: flags (Sohncke, enantiomorphic, symmorphic)
inline unsigned char point_group_index_and_category(int space_group_number) {
  // 0x20=Sohncke, 0x40=enantiomorphic, 0x80=symmorphic
  enum : unsigned char { S=0x20, E=(0x20|0x40), Y=0x80, Z=(0x20|0x80) };
  static const unsigned char indices[230] = {
     0|Z,  1|Y,  2|Z,  2|S,  2|Z,  3|Y,  3,    3|Y,  3,    4|Y,  // 1-10
     4,    4|Y,  4,    4,    4,    5|Z,  5|S,  5|S,  5|S,  5|S,  // 11-20
     5|Z,  5|Z,  5|Z,  5|S,  6|Y,  6,    6,    6,    6,    6,    // 21-30
     6,    6,    6,    6,    6|Y,  6,    6,    6|Y,  6,    6,    // 31-40
     6,    6|Y,  6,    6|Y,  6,    6,    7|Y,  7,    7,    7,    // 41-50
     7,    7,    7,    7,    7,    7,    7,    7,    7,    7,    // 51-60
     7,    7,    7,    7,    7|Y,  7,    7,    7,    7|Y,  7,    // 61-70
     7|Y,  7,    7,    7,    8|Z,  8|E,  8|S,  8|E,  8|Z,  8|S,  // 71-80
     9|Y,  9|Y, 10|Y, 10,   10,   10,   10|Y, 10,   11|Z, 11|S,  // 81-90
    11|E, 11|E, 11|S, 11|S, 11|E, 11|E, 11|Z, 11|S, 12|Y, 12,    // 91-100
    12,   12,   12,   12,   12,   12,   12|Y, 12,   12,   12,    // 101-110
    13|Y, 13,   13,   13,   13|Y, 13,   13,   13,   13|Y, 13,    // 111-120
    13|Y, 13,   14|Y, 14,   14,   14,   14,   14,   14,   14,    // 121-130
    14,   14,   14,   14,   14,   14,   14,   14,   14|Y, 14,    // 131-140
    14,   14,   15|Z, 15|E, 15|E, 15|Z, 16|Y, 16|Y, 17|Z, 17|Z,  // 141-150
    17|E, 17|E, 17|E, 17|E, 17|Z, 18|Y, 18|Y, 18,   18,   18|Y,  // 151-160
    18,   19|Y, 19,   19|Y, 19,   19|Y, 19,   20|Z, 20|E, 20|E,  // 161-170
    20|E, 20|E, 20|S, 21|Y, 22|Y, 22,   23|Z, 23|E, 23|E, 23|E,  // 171-180
    23|E, 23|S, 24|Y, 24,   24,   24,   25|Y, 25,   25|Y, 25,    // 181-190
    26|Y, 26,   26,   26,   27|Z, 27|Z, 27|Z, 27|S, 27|S, 28|Y,  // 191-200
    28,   28|Y, 28,   28|Y, 28,   28,   29|Z, 29|S, 29|Z, 29|S,  // 201-210
    29|Z, 29|E, 29|E, 29|S, 30|Y, 30|Y, 30|Y, 30,   30,   30,    // 211-220
    31|Y, 31,   31,   31,   31|Y, 31,   31,   31,   31|Y, 31     // 221-230
  };
  return indices[space_group_number-1];
}

/// @brief Get the point group for a space group.
/// @param space_group_number Space group number (1-230)
/// @return Point group of the space group
inline PointGroup point_group(int space_group_number) {
  auto n = point_group_index_and_category(space_group_number);
  return static_cast<PointGroup>(n & 0x1f);
}

/// @brief Check if a space group is Sohncke (no enantiomorphic pairs).
/// @param space_group_number Space group number (1-230)
/// @return true for 65 Sohncke space groups
inline bool is_sohncke(int space_group_number) {
  return (point_group_index_and_category(space_group_number) & 0x20) != 0;
}

/// @brief Check if a space group is enantiomorphic.
/// @param space_group_number Space group number (1-230)
/// @return true for 22 space groups (11 enantiomorphic pairs)
inline bool is_enantiomorphic(int space_group_number) {
  return (point_group_index_and_category(space_group_number) & 0x40) != 0;
}

/// @brief Check if a space group is symmorphic (no screw axes or glide planes).
/// @param space_group_number Space group number (1-230)
/// @return true for 73 symmorphic space groups
inline bool is_symmorphic(int space_group_number) {
  return (point_group_index_and_category(space_group_number) & 0x80) != 0;
}

/// @brief Inversion center of the Euclidean normalizer that is not at the origin.
/// @details Returns (0,0,0) if absent. See ch. 3.5 of ITA (2016),
/// column "Inversion through a centre at".
/// @param space_group_number Space group number (1–230).
/// @return Inversion centre translation, or (0,0,0) if none.
/// @par References
/// International Tables for Crystallography, Vol. A (2016), ch. 3.5.
/// https://doi.org/10.1107/97809553602060000933
inline Op::Tran nonzero_inversion_center(int space_group_number) {
  constexpr int D = Op::DEN;
  switch (space_group_number) {
    case 43: return {D/8, D/8, 0};
    case 80: return {D/4, 0, 0};
    case 98: return {D/4, 0, D/8};
    case 109: return {D/4, 0, 0};
    case 110: return {D/4, 0, 0};
    case 122: return {D/4, 0, D/8};
    case 210: return {D/8, D/8, D/8};
    default: return {0, 0, 0};
  }
}

/// @brief Get a basis operation (change-of-basis) string by index.
/// @param basisop_idx Index into basis operation table
/// @return Basis operation string in triplet notation, or nullptr if index is invalid
GEMMI_DLL const char* get_basisop(int basisop_idx);

/// @brief Compute a change-of-basis operator for centred-to-primitive transformation.
/// @param centring_type Bravais lattice type: 'P', 'A', 'B', 'C', 'I', 'F', 'R', 'H'
/// @return 3x3 matrix for centred-to-primitive basis change (same as inverse of z2p_op in sgtbx)
inline Op::Rot centred_to_primitive(char centring_type) {
  constexpr int D = Op::DEN;
  constexpr int H = Op::DEN / 2;
  constexpr int T = Op::DEN / 3;
  switch (centring_type) {
    case 'P': return {{{D,0,0},     {0,D,0},    {0,0,D}}};
    case 'A': return {{{-D,0,0},    {0,-H,H},   {0,H,H}}};
    case 'B': return {{{-H,0,H},    {0,-D,0},   {H,0,H}}};
    case 'C': return {{{H,H,0},     {H,-H,0},   {0,0,-D}}};
    case 'I': return {{{-H,H,H},    {H,-H,H},   {H,H,-H}}};
    case 'R': return {{{2*T,-T,-T}, {T,T,-2*T}, {T,T,T}}};
    case 'H': return {{{2*T,-T,0},  {T,T,0},    {0,0,D}}};  // not used normally
    case 'F': return {{{0,H,H},     {H,0,H},    {H,H,0}}};
    default: fail("not a centring type: ", centring_type);
  }
}


// LIST OF CRYSTALLOGRAPHIC SPACE GROUPS

/// @brief A crystallographic space group definition.
///
/// Stores the essential properties of a space group including its ITA number,
/// Hermann-Mauguin symbol, Hall symbol, and basis operation (change-of-basis from
/// reference setting). This structure is typically embedded in a static table.
struct SpaceGroup { // typically 44 bytes
  /// @brief ITA (International Tables for Crystallography) space group number (1-230).
  int number;
  /// @brief CCP4 space group number (may differ from ITA for some non-standard settings).
  int ccp4;
  /// @brief Hermann-Mauguin (international) notation, e.g., "P 1 2 1" or "P 21 21 21".
  char hm[11];
  /// @brief Extension character: ' ' (default), 'R' (rhombohedral), 'H' (hexagonal), etc.
  char ext;
  /// @brief Qualifier string for distinguishing settings, e.g., "b" for monoclinic unique axis.
  char qualifier[5];
  /// @brief Hall symbol string for generating symmetry operations.
  char hall[15];
  /// @brief Index into basis operation table for non-reference settings; 0 for reference setting.
  int basisop_idx;

  /// @brief Get extended Hermann-Mauguin notation including extension.
  /// @return String like "P 1 2 1" or "R 3:H"
  std::string xhm() const {
    std::string ret = hm;
    if (ext) {
      ret += ':';
      ret += ext;
    }
    return ret;
  }

  /// @brief Get the Bravais lattice type.
  /// @return Character: 'P', 'A', 'B', 'C', 'I', 'F' for conventional, or 'P' for primitive rhombohedral
  char centring_type() const { return ext == 'R' ? 'P' : hm[0]; }

  /// @brief Get the lattice type used in CCP4 conventions.
  /// @return Character: 'H' for hexagonal setting, otherwise first character of hm
  char ccp4_lattice_type() const { return ext == 'H' ? 'H' : hm[0]; }

  /// @brief Get a short space group symbol without redundant axis labels.
  /// @return String like "P2" (from "P 1 2 1"), "P112" (from "P 1 1 2"), or "H3" (from "R 3:H")
  std::string short_name() const {
    std::string s(hm);
    size_t len = s.size();
    if (len > 6 && s[2] == '1' && s[len - 2] == ' ' && s[len - 1] == '1')
      s = s[0] + s.substr(4, len - 4 - 2);
    if (ext == 'H')
      s[0] = 'H';
    s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
    return s;
  }

  /// @brief Get the PDB convention name for rhombohedral space groups.
  /// @return String like "R3" or "R32" (non-standard PDB notation)
  /// @note As explained in Phenix newsletter CCN_2011_01.pdf#page=12, PDB uses own symbols
  std::string pdb_name() const {
    std::string s;
    s += ccp4_lattice_type();
    s += hm+1;
    return s;
  }

  /// @brief Check if this space group is Sohncke (non-enantiomorphic).
  bool is_sohncke() const { return gemmi::is_sohncke(number); }
  /// @brief Check if this space group is enantiomorphic.
  bool is_enantiomorphic() const { return gemmi::is_enantiomorphic(number); }
  /// @brief Check if this space group is symmorphic.
  bool is_symmorphic() const { return gemmi::is_symmorphic(number); }
  /// @brief Get the point group of this space group.
  PointGroup point_group() const { return gemmi::point_group(number); }
  /// @brief Get the Hermann-Mauguin notation of the point group.
  const char* point_group_hm() const {
    return gemmi::point_group_hm(point_group());
  }
  /// @brief Get the Laue class (centrosymmetric point group).
  Laue laue_class() const { return pointgroup_to_laue(point_group()); }
  /// @brief Get the Laue class as a string in Hermann-Mauguin notation.
  const char* laue_str() const { return laue_class_str(laue_class()); }
  /// @brief Get the crystal system.
  CrystalSystem crystal_system() const {
    return gemmi::crystal_system(point_group());
  }
  /// @brief Get the crystal system as a string name.
  const char* crystal_system_str() const {
    return gemmi::crystal_system_str(crystal_system());
  }
  /// @brief Check if this space group is centrosymmetric (has an inversion center).
  bool is_centrosymmetric() const {
    return laue_to_pointgroup(laue_class()) == point_group();
  }

  /// @brief Get the unique axis for monoclinic space groups.
  /// @return 'a', 'b', or 'c' for monoclinic; '\0' for all other crystal systems
  char monoclinic_unique_axis() const {
    if (crystal_system() == CrystalSystem::Monoclinic)
      return qualifier[qualifier[0] == '-' ? 1 : 0];
    return '\0';
  }

  /// @brief Get the basis operation (change-of-basis) string.
  /// @return Triplet notation string for the basis operation, or empty for reference setting
  const char* basisop_str() const { return get_basisop(basisop_idx); }
  /// @brief Parse the basis operation into an Op.
  /// @return Op representing the change-of-basis from reference setting
  Op basisop() const { return parse_triplet(basisop_str()); }
  /// @brief Check if this is the reference setting.
  /// @return true if basisop_idx == 0 (no basis operation needed)
  bool is_reference_setting() const { return basisop_idx == 0; }

  /// @brief Get the change-of-basis operator from conventional to primitive cell.
  /// @return Op for centred-to-primitive transformation
  Op centred_to_primitive() const {
    return {gemmi::centred_to_primitive(centring_type()), {0,0,0}, 'x'};
  }

  /// @brief Get the change-of-hand operator for enantiomorphic space groups.
  /// @return Op representing point reflection through an inversion center not at the origin
  /// @note Returns identity for centrosymmetric space groups (no change of hand possible)
  Op change_of_hand_op() const {
    if (is_centrosymmetric())
      return Op::identity();
    Op::Tran t = nonzero_inversion_center(number);
    Op op{Op::inversion_rot(), {2*t[0], 2*t[1], 2*t[2]}, 'x'};
    if (!is_reference_setting()) {
      Op b = basisop();
      op = b.combine(op).combine(b.inverse());
    }
    return op;
  }

  /// @brief Generate the full group of symmetry operations from the Hall symbol.
  /// @return GroupOps with all symmetry elements (applying Dimino's algorithm)
  GroupOps operations() const { return symops_from_hall(hall); }
};

/// @brief Alternative name for a space group (for lookups).
struct SpaceGroupAltName {
  /// @brief Hermann-Mauguin symbol for this alternative name
  char hm[11];
  /// @brief Extension character (if any)
  char ext;
  /// @brief Index into main space group table
  int pos;
};

/// @brief Static lookup tables for space groups and reciprocal-space ASU definitions.
struct GEMMI_DLL spacegroup_tables {
  /// @brief Array of 564 space group entries (multiple settings per ITA number)
  static const SpaceGroup main[564];
  /// @brief Array of 28 alternative names for space group lookups
  static const SpaceGroupAltName alt_names[28];
  /// @brief CCP4 reciprocal-space ASU index for each of the 230 space groups
  static const unsigned char ccp4_hkl_asu[230];
};

/// @brief Find a space group by its CCP4 number.
/// @param ccp4 CCP4 space group number
/// @return Pointer to SpaceGroup if found, nullptr otherwise
inline const SpaceGroup* find_spacegroup_by_number(int ccp4) noexcept {
  if (ccp4 == 0)
    return &spacegroup_tables::main[0];
  for (const SpaceGroup& sg : spacegroup_tables::main)
    if (sg.ccp4 == ccp4)
      return &sg;
  return nullptr;
}

/// @brief Get a space group by CCP4 number (throws if not found).
/// @param ccp4 CCP4 space group number
/// @return Reference to SpaceGroup
/// @throw std::invalid_argument if space group not found
inline const SpaceGroup& get_spacegroup_by_number(int ccp4) {
  const SpaceGroup* sg = find_spacegroup_by_number(ccp4);
  if (sg == nullptr)
    throw std::invalid_argument("Invalid space-group number: "
                                + std::to_string(ccp4));
  return *sg;
}

/// @brief Get the reference setting (basis operation 0) for an ITA space group number.
/// @param number ITA space group number (1-230)
/// @return Reference to SpaceGroup in reference setting
/// @throw std::invalid_argument if space group number not found
inline const SpaceGroup& get_spacegroup_reference_setting(int number) {
  for (const SpaceGroup& sg : spacegroup_tables::main)
    if (sg.number == number && sg.is_reference_setting())
      return sg;
  throw std::invalid_argument("Invalid space-group number: "
                              + std::to_string(number));
}

/// @brief Find a space group by its name (Hermann-Mauguin, Hall, or alternative).
/// @param name Space group name to search for (case-insensitive variations accepted)
/// @param alpha Optional: triclinic angle to distinguish H and R settings
/// @param gamma Optional: triclinic angle to distinguish H and R settings
/// @param prefer Optional: preference string like "1H" (1st setting, hexagonal) or "2R" (2nd setting, rhombohedral)
/// @return Pointer to SpaceGroup if found, nullptr otherwise
/// @note If angles alpha and gamma are provided, they help distinguish hexagonal/rhombohedral
///       settings for trigonal space groups (e.g., "R 3" with different axis choices)
GEMMI_DLL const SpaceGroup* find_spacegroup_by_name(std::string name,
                                  double alpha=0., double gamma=0.,
                                  const char* prefer=nullptr);

/// @brief Get a space group by name (throws if not found).
/// @param name Space group name
/// @return Reference to SpaceGroup
/// @throw std::invalid_argument if space group not found
inline const SpaceGroup& get_spacegroup_by_name(const std::string& name) {
  const SpaceGroup* sg = find_spacegroup_by_name(name);
  if (sg == nullptr)
    throw std::invalid_argument("Unknown space-group name: " + name);
  return *sg;
}

/// @brief Get the P1 space group (trivial space group with identity only).
/// @return Reference to P1 space group (number 1)
inline const SpaceGroup& get_spacegroup_p1() {
  return spacegroup_tables::main[0];
}

/// @brief Find a space group matching a given set of symmetry operations.
/// @param gops Group of symmetry operations (rotation matrices and centring)
/// @return Pointer to matching SpaceGroup, or nullptr if no exact match found
inline const SpaceGroup* find_spacegroup_by_ops(const GroupOps& gops) {
  char c = gops.find_centering();
  for (const SpaceGroup& sg : spacegroup_tables::main)
    if ((c == sg.hall[0] || c == sg.hall[1]) &&
        gops.is_same_as(sg.operations()))
      return &sg;
  return nullptr;
}

/// @brief Reciprocal-space asymmetric unit (ASU) for a space group.
///
/// Defines a unique region in reciprocal space (h,k,l indices) such that
/// all equivalent reflections related by symmetry are mapped to this region.
/// This enables efficient data storage and comparison of diffraction data.
///
/// Supports 12 CCP4-standard ASU choices and TNT-specific variants (20 total).
struct ReciprocalAsu {
  /// @brief Index into CCP4 ASU definition table (0-19)
  int idx;
  /// @brief Change-of-basis rotation matrix (used if space group is not in reference setting)
  Op::Rot rot{};  // value-initialized only to avoid -Wmaybe-uninitialized
  /// @brief true if space group is in reference setting, false otherwise
  bool is_ref;

  /// @brief Construct a ReciprocalAsu from a space group.
  /// @param sg Pointer to SpaceGroup (must not be nullptr)
  /// @param tnt If true, use TNT-specific ASU definitions instead of CCP4 standard
  /// @throw std::runtime_error if sg is nullptr
  ReciprocalAsu(const SpaceGroup* sg, bool tnt=false) {
    if (sg == nullptr)
      fail("Missing space group");
    idx = spacegroup_tables::ccp4_hkl_asu[sg->number - 1];
    if (tnt) {
      idx += 10;
      is_ref = true; // TNT ASU is given wrt current (not standard) settings
    } else {
      is_ref = sg->is_reference_setting();
      if (!is_ref)
        rot = sg->basisop().rot;
    }
  }

  /// @brief Check if Miller indices are within the ASU.
  /// @param hkl Miller indices (h, k, l)
  /// @return true if hkl is in the asymmetric unit
  bool is_in(const Op::Miller& hkl) const {
    if (is_ref)
      return is_in_reference_setting(hkl[0], hkl[1], hkl[2]);
    Op::Miller r;
    for (int i = 0; i != 3; ++i)
      r[i] = rot[0][i] * hkl[0] + rot[1][i] * hkl[1] + rot[2][i] * hkl[2];
    return is_in_reference_setting(r[0], r[1], r[2]);
  }

  /// @brief Check if Miller indices are in the ASU (assuming reference setting).
  /// @param h h index
  /// @param k k index
  /// @param l l index
  /// @return true if (h,k,l) is in the ASU definition for this idx
  bool is_in_reference_setting(int h, int k, int l) const {
    switch (idx) {
      // 0-9: CCP4 hkl asu,  10-19: TNT hkl asu
      case 0: return l>0 || (l==0 && (h>0 || (h==0 && k>=0)));
      case 1: return k>=0 && (l>0 || (l==0 && h>=0));
      case 12: // orthorhombic-D
      case 2: return h>=0 && k>=0 && l>=0;
      case 3: return l>=0 && ((h>=0 && k>0) || (h==0 && k==0));
      case 14: // tetragonal-D, hexagonal-D
      case 4: return h>=k && k>=0 && l>=0;
      case 5: return (h>=0 && k>0) || (h==0 && k==0 && l>=0);
      case 16: // trigonal-D P312
      case 6: return h>=k && k>=0 && (k>0 || l>=0);
      case 17: // trigonal-D P321
      case 7: return h>=k && k>=0 && (h>k || l>=0);
      case 8: return h>=0 && ((l>=h && k>h) || (l==h && k==h));
      case 9: return k>=l && l>=h && h>=0;
      case 10: return k>0 || (k==0 && (h>0 || (h==0 && l>=0))); // triclinic
      case 11: return k>=0 && (h>0 || (h==0 && l>=0)); // monoclinic-B
      case 13: return l>=0 && ((k>=0 && h>0) || (h==0 && k==0)); // tetragonal-C, hexagonal-C
      case 15: return (k>=0 && h>0) || (h==0 && k==0 && l>=0); // trigonal-C
      case 18: return k>=0 && l>=0 && ((h>k && h>l) || (h==k && h>=l)); // cubic-T
      case 19: return h>=k && k>=l && l>=0; // cubic-O
    }
    unreachable();
  }

  /// @brief Get a human-readable string describing the ASU boundary condition.
  /// @return Condition string like "h>=0 and k>=0 and l>=0"
  const char* condition_str() const {
    switch (idx) {
      case 0: return "l>0 or (l=0 and (h>0 or (h=0 and k>=0)))";
      case 1: return "k>=0 and (l>0 or (l=0 and h>=0))";
      case 12:
      case 2: return "h>=0 and k>=0 and l>=0";
      case 3: return "l>=0 and ((h>=0 and k>0) or (h=0 and k=0))";
      case 14:
      case 4: return "h>=k and k>=0 and l>=0";
      case 5: return "(h>=0 and k>0) or (h=0 and k=0 and l>=0)";
      case 16:
      case 6: return "h>=k and k>=0 and (k>0 or l>=0)";
      case 17:
      case 7: return "h>=k and k>=0 and (h>k or l>=0)";
      case 8: return "h>=0 and ((l>=h and k>h) or (l=h and k=h))";
      case 9: return "k>=l and l>=h and h>=0";
      case 10: return "k>0 or (k==0 and (h>0 or (h=0 and l>=0)))";
      case 11: return "k>=0 and (h>0 or (h=0 and l>=0))";
      case 13: return "l>=0 and ((k>=0 and h>0) or (h=0 and k==0))";
      case 15: return "(k>=0 and h>0) or (h=0 and k==0 and l>=0)";
      case 18: return "k>=0 and l>=0 and ((h>k and h>l) or (h=k and h>=l))";
      case 19: return "h>=k and k>=l and l>=0";
    }
    unreachable();
  }

  /// @brief Map Miller indices to the ASU and return an MTZ ISYM identifier.
  /// @param hkl Miller indices
  /// @param sym_ops Array of symmetry operations to search
  /// @return Pair: (equivalent hkl in ASU, MTZ ISYM code)
  /// @note ISYM = 2*n-1 for reflections in positive ASU (Friedel +), 2*n for negative ASU (Friedel -)
  /// @note ISYM ranges from 1 to 2*|sym_ops| depending on which symmetry operation maps hkl to ASU
  std::pair<Op::Miller,int> to_asu(const Op::Miller& hkl, const std::vector<Op>& sym_ops) const {
    int isym = 0;
    for (const Op& op : sym_ops) {
      ++isym;
      Op::Miller new_hkl = op.apply_to_hkl_without_division(hkl);
      if (is_in(new_hkl))
        return {Op::divide_hkl_by_DEN(new_hkl), isym};
      ++isym;
      Op::Miller negated_new_hkl{{-new_hkl[0], -new_hkl[1], -new_hkl[2]}};
      if (is_in(negated_new_hkl))
        return {Op::divide_hkl_by_DEN(negated_new_hkl), isym};
    }
    fail("Oops, maybe inconsistent GroupOps?");
  }

  /// @brief Map Miller indices to the ASU using a GroupOps structure.
  /// @param hkl Miller indices
  /// @param gops Group of symmetry operations
  /// @return Pair: (equivalent hkl in ASU, MTZ ISYM code)
  std::pair<Op::Miller,int> to_asu(const Op::Miller& hkl, const GroupOps& gops) const {
    return to_asu(hkl, gops.sym_ops);
  }

  /// @brief Map Miller indices to the ASU and return a sign flag instead of ISYM.
  /// @param hkl Miller indices
  /// @param gops Group of symmetry operations
  /// @return Pair: (equivalent hkl in ASU, sign) where sign=true for positive/centric, false for negative Friedel pair
  /// @note For centric reflections, always returns sign=true
  std::pair<Op::Miller,bool> to_asu_sign(const Op::Miller& hkl, const GroupOps& gops) const {
    std::pair<Op::Miller,bool> neg = {{0,0,0}, true};
    for (const Op& op : gops.sym_ops) {
      Op::Miller new_hkl = op.apply_to_hkl_without_division(hkl);
      if (is_in(new_hkl))
        return {Op::divide_hkl_by_DEN(new_hkl), true};
      Op::Miller negated_new_hkl{{-new_hkl[0], -new_hkl[1], -new_hkl[2]}};
      if (is_in(negated_new_hkl))
        // don't return it yet, because for centric reflection we prefer (+)
        neg = {Op::divide_hkl_by_DEN(negated_new_hkl), false};
    }
    if (neg.second)
      fail("Oops, maybe inconsistent GroupOps?");
    return neg;
  }
};

} // namespace gemmi

namespace std {
/// @brief Hash function specialization for symmetry operations.
template<> struct hash<gemmi::Op> {
  /// @brief Compute hash of a symmetry operation.
  /// @param op Operation to hash
  /// @return Hash value combining rot and tran
  size_t operator()(const gemmi::Op& op) const {
    size_t h = 0;
    for (int i = 0; i != 3; ++i)
      for (int j = 0; j != 3; ++j)
        h = (h << 2) ^ (op.rot[i][j] + 1);
    for (int i = 0; i != 3; ++i)
      h = (h << 5) ^ op.tran[i];
    return h;
  }
};
} // namespace std

#endif

/// @file
/// @brief Unit cell and fractional/Cartesian coordinate transformations.
/// Defines the UnitCell struct and related types for crystallographic operations.
/// Provides coordinate transformation matrices, distance calculations with
/// periodic boundary conditions, and symmetry operation tracking.

// Copyright 2017 Global Phasing Ltd.
//
// Unit cell.

#ifndef GEMMI_UNITCELL_HPP_
#define GEMMI_UNITCELL_HPP_

#include <cassert>
#include <cmath>      // for cos, sin, sqrt, floor, NAN
#include <vector>
#include "math.hpp"
#include "fail.hpp"   // for fail
#include "symmetry.hpp"  // for Op, SpaceGroup

namespace gemmi {

/// Converts a symmetry operation rotation matrix to Mat33 format.
/// @param rot The integer rotation matrix from a symmetry operation (scaled by Op::DEN).
/// @return A Mat33 with the rotation matrix scaled to unit coefficients.
inline Mat33 rot_as_mat33(const Op::Rot& rot) {
  double mult = 1.0 / Op::DEN;
  return Mat33(mult * rot[0][0], mult * rot[0][1], mult * rot[0][2],
               mult * rot[1][0], mult * rot[1][1], mult * rot[1][2],
               mult * rot[2][0], mult * rot[2][1], mult * rot[2][2]);
}

/// Converts a symmetry operation to Mat33 rotation matrix format.
/// @param op The symmetry operation.
/// @return A Mat33 with the operation's rotation matrix scaled to unit coefficients.
inline Mat33 rot_as_mat33(const Op& op) { return rot_as_mat33(op.rot); }


/// Converts a symmetry operation translation to Vec3 format.
/// @param op The symmetry operation.
/// @return A Vec3 with the operation's translation scaled to unit coefficients.
inline Vec3 tran_as_vec3(const Op& op) {
  double mult = 1.0 / Op::DEN;
  return Vec3(mult * op.tran[0], mult * op.tran[1], mult * op.tran[2]);
}

/// @brief Coordinates in Angstroms - orthogonal (Cartesian) coordinates.
/// Represents a position in 3D Cartesian space. Inherits from Vec3 and provides
/// arithmetic operations that return Position objects (for type safety).
struct Position : Vec3 {
  using Vec3::Vec3;
  Position() = default;
  explicit Position(const Vec3& v) : Vec3(v) {}
  Position operator-() const { return Position(Vec3::operator-()); } ///<Negation.
  Position operator-(const Position& o) const { return Position(Vec3::operator-(o)); } ///<Subtraction.
  Position operator+(const Position& o) const { return Position(Vec3::operator+(o)); } ///<Addition.
  Position operator*(double d) const { return Position(Vec3::operator*(d)); } ///<Scalar multiplication.
  Position operator/(double d) const { return Position(Vec3::operator/(d)); } ///<Scalar division.
  Position& operator-=(const Position& o) { *this = *this - o; return *this; } ///<In-place subtraction.
  Position& operator+=(const Position& o) { *this = *this + o; return *this; } ///<In-place addition.
  Position& operator*=(double d) { *this = *this * d; return *this; } ///<In-place scalar multiplication.
  Position& operator/=(double d) { return operator*=(1.0/d); } ///<In-place scalar division.
};

/// Scalar multiplication (left-associative).
/// @param d Scalar multiplier.
/// @param v Position to scale.
/// @return Scaled position.
inline Position operator*(double d, const Position& v) { return v * d; }

/// @brief Fractional coordinates (within the unit cell).
/// Represents coordinates in the crystal cell basis (a, b, c vectors).
/// Values typically in [0, 1) but may extend outside this range for nearby cells.
struct Fractional : Vec3 {
  using Vec3::Vec3;
  Fractional() = default;
  explicit Fractional(const Vec3& v) : Vec3(v) {}
  /// Subtraction of fractional coordinates.
  Fractional operator-(const Fractional& o) const {
    return Fractional(Vec3::operator-(o));
  }
  /// Addition of fractional coordinates.
  Fractional operator+(const Fractional& o) const {
    return Fractional(Vec3::operator+(o));
  }
  /// @brief Wrap coordinates to [0, 1).
  /// Subtracts floor of each component to bring into primary unit cell.
  /// @return Wrapped fractional coordinates.
  Fractional wrap_to_unit() const {
    return {x - std::floor(x), y - std::floor(y), z - std::floor(z)};
  }
  /// @brief Wrap coordinates to (-0.5, 0.5].
  /// Subtracts nearest integer to bring close to origin (for distances).
  /// @return Wrapped fractional coordinates centered at origin.
  Fractional wrap_to_zero() const {
    return {x - std::round(x), y - std::round(y), z - std::round(z)};
  }
  /// @brief Round each component to the nearest integer.
  /// @return Rounded fractional coordinates.
  Fractional round() const {
    return {std::round(x), std::round(y), std::round(z)};
  }
  /// @brief Move each component toward zero by 1 if outside (-0.5, 0.5].
  /// Used for wrapping to the asymmetric unit.
  void move_toward_zero_by_one() {
    if (x > 0.5) x -= 1.0; else if (x < -0.5) x += 1.0;
    if (y > 0.5) y -= 1.0; else if (y < -0.5) y += 1.0;
    if (z > 0.5) z -= 1.0; else if (z < -0.5) z += 1.0;
  }
};

/// @brief Asymmetric unit filter for nearest-image searches.
enum class Asu : unsigned char {
  Same,     ///< Include only the same asymmetric unit (no symmetry).
  Different,///< Exclude the same asymmetric unit (only symmetry-related copies).
  Any       ///< Include all images (same and symmetry-related).
};

/// @brief Result of finding the nearest image of an atom under periodic boundary conditions and symmetry.
/// Stores the squared distance, PBC shifts, and symmetry operation index.
struct NearestImage {
  double dist_sq;                    ///< Squared distance in Angstroms^2.
  int pbc_shift[3] = { 0, 0, 0 };   ///< Integer shifts in a, b, c directions (periodic boundary conditions).
  int sym_idx = 0;                   ///< Index of the symmetry operation (0 = identity, 1+ = sym_ops[index-1]).

  /// @brief Compute distance from squared distance.
  /// @return Distance in Angstroms.
  double dist() const { return std::sqrt(dist_sq); }

  /// @brief Check if the image is in the same asymmetric unit.
  /// @return True if no PBC shifts and identity symmetry operation.
  bool same_asu() const {
    return pbc_shift[0] == 0 && pbc_shift[1] == 0 && pbc_shift[2] == 0 && sym_idx == 0;
  }

  /// @brief Generate a symmetry code (e.g., "1555" or "1_555").
  /// Encodes the symmetry operation index and PBC shifts in standard crystallographic notation.
  /// @param underscore If true, use format "1_555"; if false, use "1555".
  /// @return Symmetry code string.
  std::string symmetry_code(bool underscore) const {
    std::string s = std::to_string(sym_idx + 1);
    if (underscore)
      s += '_';
    if (unsigned(5 + pbc_shift[0]) <= 9 &&
        unsigned(5 + pbc_shift[1]) <= 9 &&
        unsigned(5 + pbc_shift[2]) <= 9) {  // normal, quick path
      for (int shift : pbc_shift)
        s += char('5' + shift);
    } else {                                // problematic, non-standard path
      for (int i = 0; i < 3; ++i) {
        if (i != 0 && underscore)
          s += '_';
        s += std::to_string(5 + pbc_shift[i]);
      }
    }
    return s;
  }
};


/// @brief Fractional coordinate transformation.
/// Like Transform, but operates on Fractional coordinates for type safety.
/// Used for symmetry operations and basis transformations in fractional space.
struct FTransform : Transform {
  FTransform() = default;
  FTransform(const Transform& t) : Transform(t) {}
  /// Apply transformation to fractional coordinates.
  /// @param p Fractional coordinates.
  /// @return Transformed fractional coordinates.
  Fractional apply(const Fractional& p) const {
    return Fractional(Transform::apply(p));
  }
};

/// @brief Non-crystallographic symmetry operation (such as in PDB MTRIXn records).
/// Represents a transformation for NCS (molecular symmetry not related to the crystal lattice).
struct NcsOp {
  std::string id;       ///< Identifier for this NCS operation.
  bool given;           ///< True if given explicitly (e.g., in PDB); false if derived.
  Transform tr;         ///< Transformation matrix and translation.
  /// Apply NCS operation to Cartesian coordinates.
  /// @param p Position in Cartesian coordinates.
  /// @return Transformed position.
  Position apply(const Position& p) const { return Position(tr.apply(p)); }
};

/// @brief Miller indices (hkl reciprocal space coordinates).
/// A convenient type alias for passing hkl triplets.
using Miller = std::array<int, 3>;

/// @brief Hash function for Miller indices.
/// Enables use of Miller indices in hash tables and unordered containers.
struct MillerHash {
  /// @param hkl Miller indices to hash.
  /// @return Hash value.
  std::size_t operator()(const Miller& hkl) const noexcept {
    return std::size_t((hkl[0] * 1024 + hkl[1]) * 1024 + hkl[2]);  // NOLINT misplaced cast
  }
};

/// @brief Base parameters for a unit cell (6 parameters: 3 lengths and 3 angles).
/// Stores the six independent parameters defining a crystallographic unit cell.
/// Angles are in degrees.
struct UnitCellParameters {
  double a = 1.0, b = 1.0, c = 1.0;     ///< Unit cell edge lengths in Angstroms.
  double alpha = 90.0, beta = 90.0, gamma = 90.0; ///< Unit cell angles in degrees.

  UnitCellParameters() = default;
  /// Construct from a C-style array of 6 doubles.
  /// @param par Array with [a, b, c, alpha, beta, gamma].
  explicit UnitCellParameters(const double (&par)[6]) {
    a = par[0]; b = par[1]; c = par[2]; alpha = par[3]; beta = par[4]; gamma = par[5];
  }
  /// Construct from a std::array of 6 doubles.
  /// @param par Array with [a, b, c, alpha, beta, gamma].
  explicit UnitCellParameters(const std::array<double,6>& par) {
    a = par[0]; b = par[1]; c = par[2]; alpha = par[3]; beta = par[4]; gamma = par[5];
  }

  /// @brief Exact equality comparison.
  /// @param o Other unit cell parameters.
  /// @return True if all parameters match exactly.
  bool operator==(const UnitCellParameters& o) const {
    return a == o.a && b == o.b && c == o.c &&
           alpha == o.alpha && beta == o.beta && gamma == o.gamma;
  }
  /// @brief Inequality comparison.
  /// @param o Other unit cell parameters.
  /// @return True if any parameter differs.
  bool operator!=(const UnitCellParameters& o) const { return !operator==(o); }

  /// @brief Approximate equality comparison.
  /// @param o Other unit cell parameters.
  /// @param epsilon Tolerance for all differences.
  /// @return True if all parameters differ by less than epsilon.
  bool approx(const UnitCellParameters& o, double epsilon) const {
    auto eq = [&](double x, double y) { return std::fabs(x - y) < epsilon; };
    return eq(a, o.a) && eq(b, o.b) && eq(c, o.c) &&
           eq(alpha, o.alpha) && eq(beta, o.beta) && eq(gamma, o.gamma);
  }
};

/// @brief Unit cell with pre-calculated transformation matrices and properties.
/// Stores crystallographic unit cell parameters (a, b, c, alpha, beta, gamma)
/// and pre-computes the orthogonalization and fractionalization transformation
/// matrices, cell volume, reciprocal cell parameters, and symmetry operations.
///
/// The orthogonalization matrix converts fractional to Cartesian coordinates
/// using the PDB convention (a-axis along X, a*-axis along Z).
/// The fractionalization matrix is its inverse.
///
/// Symmetry operations can include crystallographic symmetry (space group)
/// and non-crystallographic symmetry (NCS), stored as fractional transformations.
///
/// For non-crystalline structures (NMR), the default dummy cell 1×1×1 is used.
struct UnitCell : UnitCellParameters {
  UnitCell() = default;
  /// Construct from six cell parameters.
  /// @param a_ Edge length a (Angstroms).
  /// @param b_ Edge length b (Angstroms).
  /// @param c_ Edge length c (Angstroms).
  /// @param alpha_ Angle alpha (degrees).
  /// @param beta_ Angle beta (degrees).
  /// @param gamma_ Angle gamma (degrees).
  UnitCell(double a_, double b_, double c_,
           double alpha_, double beta_, double gamma_) {
    set(a_, b_, c_, alpha_, beta_, gamma_);
  }
  /// Construct from an array of 6 doubles.
  /// @param v Array with [a, b, c, alpha, beta, gamma].
  UnitCell(const std::array<double, 6>& v) { set_from_array(v); }

  Transform orth;                    ///< Orthogonalization matrix (fractional -> Cartesian).
  Transform frac;                    ///< Fractionalization matrix (Cartesian -> fractional), inverse of orth.
  double volume = 1.0;               ///< Unit cell volume in Angstroms^3.
  double ar = 1.0, br = 1.0, cr = 1.0; ///< Reciprocal cell edge lengths (a*, b*, c*).
  double cos_alphar = 0.0, cos_betar = 0.0, cos_gammar = 0.0; ///< Cosines of reciprocal cell angles.
  bool explicit_matrices = false;    ///< True if orthogonalization matrices were explicitly set (non-standard settings).
  short cs_count = 0;                ///< Count of crystallographic symmetry operations (excluding identity).
  std::vector<FTransform> images;    ///< Symmetry operations (crystallographic and NCS) in fractional coordinates.

  /// @brief Check if this is a crystalline structure.
  /// Returns false for non-crystalline structures (e.g., NMR) marked with dummy 1×1×1 cell.
  /// Checks both cell parameter a and the fractionalization matrix for consistency.
  /// @return True if a != 1.0 and frac.mat[0][0] != 1.0.
  bool is_crystal() const { return a != 1.0 && frac.mat[0][0] != 1.0; }

  /// @brief Check if cell parameters are similar to another cell.
  /// Lengths are compared using relative tolerance; angles using absolute tolerance.
  /// @param o Other unit cell.
  /// @param rel Relative tolerance for edge lengths.
  /// @param deg Absolute tolerance for angles in degrees.
  /// @return True if all parameters are within tolerance.
  bool is_similar(const UnitCell& o, double rel, double deg) const {
    auto siml = [&](double x, double y) { return std::fabs(x - y) < rel * std::max(x, y); };
    auto sima = [&](double x, double y) { return std::fabs(x - y) < deg; };
    return siml(a, o.a) && siml(b, o.b) && siml(c, o.c) &&
           sima(alpha, o.alpha) && sima(beta, o.beta) && sima(gamma, o.gamma);
  }

  /// @brief Calculate derived properties (volume, reciprocal cell, transformation matrices).
  /// Computes cell volume, reciprocal cell parameters, and orthogonalization/fractionalization
  /// matrices using the Giacovazzo formulas. Angles are converted from degrees to radians.
  /// Must be called after setting cell parameters.
  void calculate_properties() {
    // ensure exact values for right angles
    double cos_alpha = alpha == 90. ? 0. : std::cos(rad(alpha));
    double cos_beta  = beta  == 90. ? 0. : std::cos(rad(beta));
    double cos_gamma = gamma == 90. ? 0. : std::cos(rad(gamma));
    double sin_alpha = alpha == 90. ? 1. : std::sin(rad(alpha));
    double sin_beta  = beta  == 90. ? 1. : std::sin(rad(beta));
    double sin_gamma = gamma == 90. ? 1. : std::sin(rad(gamma));
    if (sin_alpha == 0 || sin_beta == 0 || sin_gamma == 0)
      fail("Impossible angle - N*180deg.");

    // volume - formula from Giacovazzo p.62
    volume = a * b * c * std::sqrt(1 - cos_alpha * cos_alpha
                                   - cos_beta * cos_beta - cos_gamma * cos_gamma
                                   + 2 * cos_alpha * cos_beta * cos_gamma);

    // reciprocal parameters a*, b*, ... (Giacovazzo, p. 64)
    ar = b * c * sin_alpha / volume;
    br = a * c * sin_beta / volume;
    cr = a * b * sin_gamma / volume;
    double cos_alphar_sin_beta = (cos_beta * cos_gamma - cos_alpha) / sin_gamma;
    cos_alphar = cos_alphar_sin_beta / sin_beta;
    //cos_alphar = (cos_beta * cos_gamma - cos_alpha) / (sin_beta * sin_gamma);
    cos_betar = (cos_alpha * cos_gamma - cos_beta) / (sin_alpha * sin_gamma);
    cos_gammar = (cos_alpha * cos_beta - cos_gamma) / (sin_alpha * sin_beta);

    if (explicit_matrices)
      return;

    // The orthogonalization matrix we use is described in ITfC B p.262:
    // "An alternative mode of orthogonalization, used by the Protein
    // Data Bank and most programs, is to align the a1 axis of the unit
    // cell with the Cartesian X_1 axis, and to align the a*_3 axis with the
    // Cartesian X_3 axis."
    double sin_alphar = std::sqrt(1.0 - cos_alphar * cos_alphar);
    orth.mat = {a,  b * cos_gamma,  c * cos_beta,
                0., b * sin_gamma, -c * cos_alphar_sin_beta,
                0., 0.           ,  c * sin_beta * sin_alphar};
    orth.vec = {0., 0., 0.};

    double o12 = -cos_gamma / (sin_gamma * a);
    double o13 = -(cos_gamma * cos_alphar_sin_beta + cos_beta * sin_gamma)
                  / (sin_alphar * sin_beta * sin_gamma * a);
    double o23 = cos_alphar / (sin_alphar * sin_gamma * b);
    frac.mat = {1 / a,  o12,                 o13,
                0.,     1 / orth.mat[1][1],  o23,
                0.,     0.,                  1 / orth.mat[2][2]};
    frac.vec = {0., 0., 0.};
  }

  /// @brief Get cosine of alpha angle.
  /// Converts alpha from degrees to radians and computes cosine.
  /// @return cos(alpha) where alpha is in radians.
  double cos_alpha() const { return alpha == 90. ? 0. : std::cos(rad(alpha)); }

  /// @brief Calculate B matrix for X-ray crystallography.
  /// @details Returns the B matrix in the Busing & Levy (1967) convention (PDB convention),
  /// not the cctbx convention. Used in computing structure factors and Debye-Waller factors.
  /// @return 3×3 matrix B.
  /// @see https://dials.github.io/documentation/conventions.html
  /// @par References
  /// Busing, W.R. & Levy, H.A. (1967). Angle calculations for 3- and 4-circle
  /// X-ray and neutron diffractometers. Acta Cryst. 22, 457–464.
  /// https://doi.org/10.1107/S0365110X67000970
  Mat33 calculate_matrix_B() const {
    double sin_gammar = std::sqrt(1 - cos_gammar * cos_gammar);
    double sin_betar = std::sqrt(1 - cos_betar * cos_betar);
    return Mat33(ar, br * cos_gammar, cr * cos_betar,
                 0., br * sin_gammar, -cr * sin_betar * cos_alpha(),
                 0., 0., 1.0 / c);
  }

  /// @brief Calculate equivalent isotropic displacement factor (B_eq).
  /// @details Converts a non-orthogonal anisotropic displacement tensor to an isotropic value.
  /// @par References
  /// Fischer, R.X. & Tillmanns, E. (1988). The equivalent isotropic displacement factor.
  /// Acta Cryst. C44, 775–776. https://doi.org/10.1107/S0108270188007712
  /// @param ani Anisotropic displacement tensor (non-orthogonalized, e.g., from SmallStructure::Site).
  ///            Should NOT be the orthogonal tensor from Atom.
  /// @return Equivalent isotropic displacement factor.
  double calculate_u_eq(const SMat33<double>& ani) const {
    double aar = a * ar;
    double bbr = b * br;
    double ccr = c * cr;
    // it could be optimized using orth.mat[0][1] and orth.mat[0][2]
    double cos_beta  = beta  == 90. ? 0. : std::cos(rad(beta));
    double cos_gamma = gamma == 90. ? 0. : std::cos(rad(gamma));
    return 1/3. * (sq(aar) * ani.u11 + sq(bbr) * ani.u22 + sq(ccr) * ani.u33 +
                   2 * (aar * bbr * cos_gamma * ani.u12 +
                        aar * ccr * cos_beta * ani.u13 +
                        bbr * ccr * cos_alpha() * ani.u23));
  }

  /// @brief Set fractionalization matrix from external source.
  /// Used to incorporate explicit SCALE records (PDB) or _atom_sites.fract_transf_*
  /// (mmCIF) when they differ significantly from calculated values.
  /// Validates input against suspicious values before acceptance.
  /// @param f External fractionalization transformation.
  void set_matrices_from_fract(const Transform& f) {
    // mmCIF _atom_sites.fract_transf_* and PDB SCALEn records usually contain
    // fewer significant digits than the unit cell parameters, and sometimes are
    // just wrong. Use them only if we seem to have non-standard crystal frame.
    if (f.mat.approx(frac.mat, 1e-4) && f.vec.approx(frac.vec, 1e-6))
      return;
    // The SCALE record is sometimes incorrect. Here we only catch cases
    // when CRYST1 is set as for non-crystal and SCALE is very suspicious.
    if (frac.mat[0][0] == 1.0 && (f.mat[0][0] == 0.0 || f.mat[0][0] > 1.0))
      return;
    frac = f;
    orth = f.inverse();
    explicit_matrices = true;
  }

  /// @brief Set unit cell from six parameters and compute all derived properties.
  /// Ignores empty or partial CRYST1 records (gamma=0).
  /// @param a_ Edge length a (Angstroms).
  /// @param b_ Edge length b (Angstroms).
  /// @param c_ Edge length c (Angstroms).
  /// @param alpha_ Angle alpha (degrees).
  /// @param beta_ Angle beta (degrees).
  /// @param gamma_ Angle gamma (degrees).
  void set(double a_, double b_, double c_,
           double alpha_, double beta_, double gamma_) {
    if (gamma_ == 0.0)  // ignore empty/partial CRYST1 (example: 3iyp)
      return;
    a = a_;
    b = b_;
    c = c_;
    alpha = alpha_;
    beta = beta_;
    gamma = gamma_;
    calculate_properties();
  }

  /// @brief Set unit cell from UnitCellParameters object.
  /// @param p Cell parameters to copy.
  void set_from_parameters(const UnitCellParameters& p) {
    set(p.a, p.b, p.c, p.alpha, p.beta, p.gamma);
  }

  /// @brief Set unit cell from array of six doubles.
  /// @param v Array with [a, b, c, alpha, beta, gamma].
  void set_from_array(const std::array<double,6>& v) { set(v[0], v[1], v[2], v[3], v[4], v[5]); }

  /// @brief Set unit cell from three edge vectors.
  /// Computes cell parameters from the lengths and angles between vectors.
  /// @param va First lattice vector (typically a).
  /// @param vb Second lattice vector (typically b).
  /// @param vc Third lattice vector (typically c).
  void set_from_vectors(const Vec3& va, const Vec3& vb, const Vec3& vc) {
    set(va.length(), vb.length(), vc.length(),
        deg(vb.angle(vc)), deg(vc.angle(va)), deg(va.angle(vb)));
  }

  /// @brief Transform unit cell to a different basis using a change-of-basis operation.
  /// Applies a symmetry operation (rotation + translation) to change the coordinate system.
  /// The new cell is computed from the transformed lattice vectors.
  /// @param op Change-of-basis operation (typically a crystallographic symmetry operation).
  /// @param set_images If true, also transform the stored symmetry operations.
  /// @return New unit cell in the transformed basis.
  UnitCell changed_basis_backward(const Op& op, bool set_images) {
    Mat33 mat = orth.mat.multiply(rot_as_mat33(op));
    UnitCell new_cell;
    new_cell.set_from_vectors(mat.column_copy(0),
                              mat.column_copy(1),
                              mat.column_copy(2));
    if (set_images && !images.empty()) {
      new_cell.images.reserve(images.size());
      Transform tr{rot_as_mat33(op), tran_as_vec3(op)};
      Transform tr_inv = tr.inverse();
      for (const FTransform& im : images)
        new_cell.images.push_back(tr.combine(im).combine(tr_inv));
    }
    return new_cell;
  }

  /// @brief Transform unit cell using inverse of a basis operation.
  /// Equivalent to changed_basis_backward(op.inverse(), set_images).
  /// @param op Change-of-basis operation.
  /// @param set_images If true, also transform the stored symmetry operations.
  /// @return New unit cell in the transformed basis.
  UnitCell changed_basis_forward(const Op& op, bool set_images) {
    return changed_basis_backward(op.inverse(), set_images);
  }

  /// @brief Check if unit cell is compatible with a set of symmetry operations.
  /// Verifies that the metric tensor is preserved under all operations.
  /// @param gops Group operations to check.
  /// @param eps Tolerance for metric tensor differences.
  /// @return True if all operations preserve the metric tensor.
  bool is_compatible_with_groupops(const GroupOps& gops, double eps=1e-3) const {
    std::array<double,6> metric = metric_tensor().elements_voigt();
    for (const Op& op : gops.sym_ops) {
      Mat33 m = orth.mat.multiply(rot_as_mat33(op));
      std::array<double,6> other = {{
        m.column_dot(0,0), m.column_dot(1,1), m.column_dot(2,2),
        m.column_dot(1,2), m.column_dot(0,2), m.column_dot(0,1)
      }};
      for (int i = 0; i < 6; ++i)
        if (std::fabs(metric[i] - other[i]) > eps)
          return false;
    }
    return true;
  }

  /// @brief Check if unit cell is compatible with a space group.
  /// @param sg Space group to check (may be null).
  /// @param eps Tolerance for metric tensor differences.
  /// @return True if space group is non-null and all its operations preserve the metric tensor.
  bool is_compatible_with_spacegroup(const SpaceGroup* sg, double eps=1e-3) const {
    return sg ? is_compatible_with_groupops(sg->operations(), eps) : false;
  }

  /// @brief Set crystallographic symmetry operations from a GroupOps object.
  /// Clears existing images and populates with all space group operations except identity.
  /// @param group_ops Group operations (e.g., from a space group).
  void set_cell_images_from_groupops(const GroupOps& group_ops) {
    images.clear();
    cs_count = (short) group_ops.order() - 1;
    images.reserve(cs_count);
    for (Op op : group_ops)
      if (op != Op::identity())
        images.push_back(Transform{rot_as_mat33(op), tran_as_vec3(op)});
  }

  /// @brief Set crystallographic symmetry operations from a space group.
  /// @param sg Space group (may be null; clears images if so).
  void set_cell_images_from_spacegroup(const SpaceGroup* sg) {
    if (sg) {
      set_cell_images_from_groupops(sg->operations());
    } else {
      images.clear();
      cs_count = 0;
    }
  }

  /// @brief Add non-crystallographic symmetry (NCS) operations to existing crystallographic symmetry.
  /// Generates the Cartesian product of CS and NCS operations.
  /// @param ncs List of non-crystallographic symmetry operations.
  /// @pre cs_count must equal images.size() before calling.
  void add_ncs_images_to_cs_images(const std::vector<NcsOp>& ncs) {
    assert(cs_count == (short) images.size());
    for (const NcsOp& ncs_op : ncs)
      if (!ncs_op.given) {
        // We need it to operates on fractional, not orthogonal coordinates.
        FTransform f = frac.combine(ncs_op.tr.combine(orth));
        images.push_back(f);
        for (int i = 0; i < cs_count; ++i)
          images.push_back(images[i].combine(f));
      }
  }

  /// @brief Extract non-crystallographic symmetry operations from images.
  /// Returns the subset of operations that are NCS (not crystallographic symmetry).
  /// @return Vector of NCS transformation in fractional coordinates.
  std::vector<FTransform> get_ncs_transforms() const {
    std::vector<FTransform> ncs;
    for (size_t n = cs_count; n < images.size(); n += cs_count + 1)
      ncs.push_back(images[n]);
    return ncs;
  }

  /// @brief Convert fractional coordinates to Cartesian (orthogonal).
  /// @param f Fractional coordinates.
  /// @return Position in Cartesian coordinates.
  Position orthogonalize(const Fractional& f) const {
    return Position(orth.apply(f));
  }

  /// @brief Convert Cartesian coordinates to fractional.
  /// @param o Position in Cartesian coordinates.
  /// @return Fractional coordinates.
  Fractional fractionalize(const Position& o) const {
    return Fractional(frac.apply(o));
  }

  /// @brief Convert fractional displacement to Cartesian.
  /// Applied to differences only; does not include translation vector.
  /// Guarantees: orthogonalize_difference(a-b) == orthogonalize(a) - orthogonalize(b)
  /// The translation shift (frac.vec) can be non-zero in non-standard settings and is not applied here.
  /// @param delta Fractional displacement vector.
  /// @return Cartesian displacement vector.
  Position orthogonalize_difference(const Fractional& delta) const {
    return Position(orth.mat.multiply(delta));
  }

  /// @brief Convert Cartesian displacement to fractional.
  /// Inverse operation of orthogonalize_difference.
  /// @param delta Cartesian displacement vector.
  /// @return Fractional displacement vector.
  Fractional fractionalize_difference(const Position& delta) const {
    return Fractional(frac.mat.multiply(delta));
  }

  /// @brief Compute the bounding box in Cartesian coordinates from a fractional box.
  /// A cuboid in fractional coordinates becomes a parallelepiped in Cartesian space.
  /// All 8 corners of the fractional box are transformed to find the Cartesian bounding box.
  /// @param f Bounding box in fractional coordinates.
  /// @return Bounding box in Cartesian coordinates.
  Box<Position> orthogonalize_box(const Box<Fractional>& f) const {
    Box<Position> r;
    r.minimum = orthogonalize(f.minimum);
    r.maximum = orthogonalize(f.maximum);
    if (alpha != 90. || beta == 90. || gamma == 90.) {
      r.extend(orthogonalize({f.minimum.x, f.minimum.y, f.maximum.z}));
      r.extend(orthogonalize({f.minimum.x, f.maximum.y, f.maximum.z}));
      r.extend(orthogonalize({f.minimum.x, f.maximum.y, f.minimum.z}));
      r.extend(orthogonalize({f.maximum.x, f.maximum.y, f.minimum.z}));
      r.extend(orthogonalize({f.maximum.x, f.minimum.y, f.minimum.z}));
      r.extend(orthogonalize({f.maximum.x, f.minimum.y, f.maximum.z}));
    }
    return r;
  }

  /// @brief Compose a fractional transformation into a Cartesian transformation.
  /// Converts from fractional to orthogonal space: T_orth = O * T_frac * F,
  /// where O is orthogonalization and F is fractionalization matrix.
  /// @param ftr Transformation in fractional coordinates.
  /// @return Equivalent transformation in Cartesian coordinates.
  Transform orthogonalize_transform(const FTransform& ftr) const {
    return orth.combine(ftr.combine(frac));
  }

  /// @brief Convert a symmetry operation to a Cartesian transformation.
  /// @param op Crystallographic symmetry operation.
  /// @return Equivalent transformation in Cartesian coordinates.
  Transform op_as_transform(const Op& op) const {
    return orthogonalize_transform(Transform{rot_as_mat33(op), tran_as_vec3(op)});
  }

  /// @brief Compute squared distance between two fractional coordinates.
  /// Applies periodic boundary conditions (wraps difference to (-0.5, 0.5]).
  /// @param pos1 First position in fractional coordinates.
  /// @param pos2 Second position in fractional coordinates.
  /// @return Squared distance in Angstroms^2.
  double distance_sq(const Fractional& pos1, const Fractional& pos2) const {
    Fractional diff = (pos1 - pos2).wrap_to_zero();
    return orthogonalize_difference(diff).length_sq();
  }

  /// @brief Compute squared distance between two Cartesian coordinates.
  /// Converts to fractional, then applies PBC.
  /// @param pos1 First position in Cartesian coordinates.
  /// @param pos2 Second position in Cartesian coordinates.
  /// @return Squared distance in Angstroms^2.
  double distance_sq(const Position& pos1, const Position& pos2) const {
    return distance_sq(fractionalize(pos1), fractionalize(pos2));
  }

  /// @brief Compute volume per asymmetric unit.
  /// For crystalline structures, divides total volume by the number of asymmetric units.
  /// @return Volume per asymmetric unit, or NaN for non-crystalline structures.
  double volume_per_image() const {
    return is_crystal() ? volume / (1 + images.size()) : NAN;
  }

  /// @brief Helper function: search for nearest image under PBC and update result.
  /// Applies periodic boundary conditions by wrapping the difference vector,
  /// then computes the distance and updates the image if closer than current.
  /// @param diff Fractional displacement (moved to find nearest image).
  /// @param image On input, contains current best distance; updated if better found.
  /// @return True if a closer image was found.
  /// @private
  bool search_pbc_images(Fractional&& diff, NearestImage& image) const {
    int neg_shift[3] = {0, 0, 0};
    if (is_crystal()) {
      for (int j = 0; j < 3; ++j)
        neg_shift[j] = iround(diff.at(j));
      diff.x -= neg_shift[0];
      diff.y -= neg_shift[1];
      diff.z -= neg_shift[2];
    }
    Position orth_diff = orthogonalize_difference(diff);
    double dsq = orth_diff.length_sq();
    if (dsq < image.dist_sq) {
      image.dist_sq = dsq;
      for (int j = 0; j < 3; ++j)
        image.pbc_shift[j] = -neg_shift[j];
      return true;
    }
    return false;
  }

  /// @brief Find the nearest image of an atom under periodic boundary conditions and symmetry.
  /// Searches all unit cell translations and all symmetry operations to find the closest image.
  /// @param ref Reference position in Cartesian coordinates.
  /// @param pos Position to find nearest image of (Cartesian).
  /// @param asu Filter: whether to include the same or different asymmetric units.
  /// @return NearestImage containing squared distance, PBC shifts, and symmetry operation index.
  NearestImage find_nearest_image(const Position& ref, const Position& pos, Asu asu) const {
    NearestImage image;
    if (asu == Asu::Different)
      image.dist_sq = INFINITY;
    else
      image.dist_sq = ref.dist_sq(pos);
    if (asu == Asu::Same)
      return image;
    Fractional fpos = fractionalize(pos);
    Fractional fref = fractionalize(ref);
    search_pbc_images(fpos - fref, image);
    if (asu == Asu::Different &&
        image.pbc_shift[0] == 0 && image.pbc_shift[1] == 0 && image.pbc_shift[2] == 0)
      image.dist_sq = INFINITY;
    for (int n = 0; n != static_cast<int>(images.size()); ++n)
      if (search_pbc_images(images[n].apply(fpos) - fref, image))
        image.sym_idx = n + 1;
    return image;
  }

  /// @brief Apply or unapply a symmetry operation to fractional coordinates.
  /// @param fpos Fractional position (modified in place).
  /// @param image_idx Symmetry operation index (0 = identity, 1+ = images[index-1]).
  /// @param inverse If true, apply inverse operation; if false, apply forward.
  void apply_transform(Fractional& fpos, int image_idx, bool inverse) const {
    if (image_idx > 0) {
      const FTransform& t = images.at(image_idx - 1);
      if (!inverse)
        fpos = t.apply(fpos);
      else
        fpos = FTransform(t.inverse()).apply(fpos);
    }
  }

  /// @brief Find nearest image of a fractional coordinate under PBC for a given symmetry.
  /// Applies a specific symmetry operation and finds the nearest translation of the result.
  /// @param fref Reference position in fractional coordinates.
  /// @param fpos Position to find nearest image of (fractional).
  /// @param image_idx Symmetry operation index (0 = identity).
  /// @return NearestImage with distance and PBC shifts for this symmetry.
  NearestImage find_nearest_pbc_image(const Fractional& fref, Fractional fpos,
                                      int image_idx=0) const {
    NearestImage sym_image;
    sym_image.dist_sq = INFINITY;
    sym_image.sym_idx = image_idx;
    apply_transform(fpos, image_idx, false);
    search_pbc_images(fpos - fref, sym_image);
    return sym_image;
  }

  /// @brief Find nearest image of a Cartesian position under PBC for a given symmetry.
  /// @param ref Reference position in Cartesian coordinates.
  /// @param pos Position to find nearest image of (Cartesian).
  /// @param image_idx Symmetry operation index (0 = identity).
  /// @return NearestImage with distance and PBC shifts for this symmetry.
  NearestImage find_nearest_pbc_image(const Position& ref, const Position& pos,
                                      int image_idx=0) const {
    return find_nearest_pbc_image(fractionalize(ref), fractionalize(pos), image_idx);
  }

  /// @brief Find all nearby images of a position within a given distance.
  /// Returns all images (under PBC shifts near the nearest) within the specified distance.
  /// @param fref Reference position in fractional coordinates.
  /// @param dist Distance cutoff in Angstroms.
  /// @param fpos Position to find images of (fractional).
  /// @param image_idx Symmetry operation index (0 = identity).
  /// @return Vector of NearestImage objects for all nearby translations within distance.
  std::vector<NearestImage> find_nearest_pbc_images(const Fractional& fref, double dist,
                                                    const Fractional& fpos, int image_idx) const {
    std::vector<NearestImage> results;
    NearestImage im = find_nearest_pbc_image(fref, fpos, image_idx);
    int sh[3] = {im.pbc_shift[0], im.pbc_shift[1], im.pbc_shift[2]};
    for (im.pbc_shift[0] = sh[0]-1; im.pbc_shift[0] <= sh[0]+1; ++im.pbc_shift[0])
      for (im.pbc_shift[1] = sh[1]-1; im.pbc_shift[1] <= sh[1]+1; ++im.pbc_shift[1])
        for (im.pbc_shift[2] = sh[2]-1; im.pbc_shift[2] <= sh[2]+1; ++im.pbc_shift[2]) {
          Fractional shift(im.pbc_shift[0], im.pbc_shift[1], im.pbc_shift[2]);
          im.dist_sq = orthogonalize_difference(fpos - fref + shift).length_sq();
          if (im.dist_sq <= sq(dist))
            results.push_back(im);
        }
    return results;
  }

  /// @brief Convert fractional position to Cartesian, applying PBC.
  /// Takes a fractional position that may be outside [0, 1) and returns
  /// the nearest equivalent position when converted to Cartesian coordinates,
  /// relative to a reference position.
  /// @param ref Reference position in Cartesian coordinates.
  /// @param fpos Fractional position (may be outside primary cell).
  /// @return Equivalent Cartesian position (nearest to ref).
  Position orthogonalize_in_pbc(const Position& ref,
                                const Fractional& fpos) const {
    Fractional fref = fractionalize(ref);
    return orthogonalize_difference((fpos - fref).wrap_to_zero()) + ref;
  }

  /// @brief Find the nearest PBC position of a point under a given symmetry operation.
  /// Applies a symmetry operation and then accounts for periodic boundary conditions.
  /// @param ref Reference position in Cartesian coordinates.
  /// @param pos Position to transform (Cartesian).
  /// @param image_idx Symmetry operation index (0 = identity).
  /// @param inverse If true, apply inverse symmetry operation.
  /// @return Nearest equivalent position in Cartesian coordinates.
  Position find_nearest_pbc_position(const Position& ref, const Position& pos,
                                     int image_idx, bool inverse=false) const {
    Fractional fpos = fractionalize(pos);
    apply_transform(fpos, image_idx, inverse);
    return orthogonalize_in_pbc(ref, fpos);
  }

  /// @brief Apply a NearestImage transformation to fractional coordinates.
  /// Applies both the symmetry operation and PBC shift from a NearestImage result.
  /// @param im NearestImage from a previous search.
  /// @param fpos Fractional position to transform.
  /// @return Transformed fractional position.
  Fractional fract_image(const NearestImage& im, Fractional fpos) {
    apply_transform(fpos, im.sym_idx, false);
    return fpos + Fractional(im.pbc_shift[0], im.pbc_shift[1], im.pbc_shift[2]);
  }

  /// @brief Determine if a position is on a special crystallographic site.
  /// Counts how many independent symmetry operations map this position to nearby locations
  /// (within max_dist). A special position has symmetry-equivalent copies very close by.
  /// @param fpos Position in fractional coordinates.
  /// @param max_dist Maximum distance (Angstroms) to consider as overlapping.
  /// @return Number of nearby symmetry-equivalent positions (0 = none, 3 = 4-fold axis, etc.).
  /// @pre is_crystal() must be true.
  int is_special_position(const Fractional& fpos, double max_dist) const {
    const double max_dist_sq = max_dist * max_dist;
    int n = 0;
    for (const FTransform& image : images) {
      Fractional fdiff = (image.apply(fpos) - fpos).wrap_to_zero();
      if (orthogonalize_difference(fdiff).length_sq() < max_dist_sq)
        ++n;
    }
    return n;
  }

  /// @brief Determine if a Cartesian position is on a special crystallographic site.
  /// @param pos Position in Cartesian coordinates.
  /// @param max_dist Maximum distance (Angstroms) to consider as overlapping (default 0.8).
  /// @return Number of nearby symmetry-equivalent positions.
  int is_special_position(const Position& pos, double max_dist = 0.8) const {
    return is_special_position(fractionalize(pos), max_dist);
  }

  /// @brief Calculate 1/d^2 for a reflection with floating-point indices.
  /// Computes the reciprocal d-spacing squared: 1/d^2 = (2*sin(theta)/lambda)^2.
  /// Uses floating-point indices (for MTZ files which may store fractional indices).
  /// @param h Miller index h (may be fractional).
  /// @param k Miller index k (may be fractional).
  /// @param l Miller index l (may be fractional).
  /// @return 1/d^2 in (Angstroms)^(-2).
  double calculate_1_d2_double(double h, double k, double l) const {
    double arh = ar * h;
    double brk = br * k;
    double crl = cr * l;
    return arh * arh + brk * brk + crl * crl + 2 * (arh * brk * cos_gammar +
                                                    arh * crl * cos_betar +
                                                    brk * crl * cos_alphar);
  }

  /// @brief Calculate 1/d^2 for integer Miller indices.
  /// @param hkl Miller indices.
  /// @return 1/d^2 in (Angstroms)^(-2).
  double calculate_1_d2(const Miller& hkl) const {
    return calculate_1_d2_double(hkl[0], hkl[1], hkl[2]);
  }

  /// @brief Calculate d-spacing for a reflection.
  /// d = lambda/(2*sin(theta)). This formula gives the real-space distance
  /// between planes perpendicular to the reciprocal lattice vector hkl.
  /// @param hkl Miller indices.
  /// @return d-spacing in Angstroms.
  double calculate_d(const Miller& hkl) const {
    return 1.0 / std::sqrt(calculate_1_d2(hkl));
  }

  /// @brief Calculate (sin(theta)/lambda)^2 for a reflection.
  /// Also known as 1/(4*d^2). Used in structure factor calculations.
  /// @param hkl Miller indices.
  /// @return (sin(theta)/lambda)^2 in (Angstroms)^(-2).
  double calculate_stol_sq(const Miller& hkl) const {
    return 0.25 * calculate_1_d2(hkl);
  }

  /// @brief Compute the metric tensor (Gram matrix) of the cell.
  /// The metric tensor describes the dot products of the lattice vectors.
  /// G_ij = a_i · a_j, with elements in Voigt notation: [G11, G22, G33, G12, G13, G23].
  /// @return Symmetric 3×3 matrix (metric tensor).
  /// @see https://dictionary.iucr.org/Metric_tensor
  SMat33<double> metric_tensor() const {
    // the order in SMat33 is ... m12 m13 m23 -> a.a b.b c.c a.b a.c b.c
    return {a*a, b*b, c*c, a*orth.mat[0][1], a*orth.mat[0][2], b*c*cos_alpha()};
  }

  /// @brief Compute the reciprocal metric tensor.
  /// The reciprocal metric tensor for the reciprocal cell.
  /// @return Symmetric 3×3 matrix (reciprocal metric tensor).
  SMat33<double> reciprocal_metric_tensor() const {
    return {ar*ar, br*br, cr*cr, ar*br*cos_gammar, ar*cr*cos_betar, br*cr*cos_alphar};
  }

  /// @brief Construct the reciprocal unit cell.
  /// Returns a new UnitCell with parameters (a*, b*, c*, alpha*, beta*, gamma*).
  /// @return Reciprocal cell.
  UnitCell reciprocal() const {
    auto acosd = [](double x) { return deg(std::acos(x)); };
    return UnitCell(ar, br, cr,
                    acosd(cos_alphar), acosd(cos_betar), acosd(cos_gammar));
  }

  /// @brief Get maximum Miller indices for a minimum d-spacing.
  /// Useful for defining resolution limits in reciprocal space.
  /// @param dmin Minimum d-spacing in Angstroms.
  /// @return Miller indices [h_max, k_max, l_max] to achieve dmin resolution.
  Miller get_hkl_limits(double dmin) const {
    return {{int(a / dmin), int(b / dmin), int(c / dmin)}};
  }

  /// @brief Get orthogonalization matrix for a primitive cell.
  /// Adjusts the standard orthogonalization matrix for non-primitive centring.
  /// @param centring_type Crystal centring type ('P', 'C', 'B', 'A', 'I', 'F', 'R', 'H').
  /// @return Orthogonalization matrix for the primitive cell.
  Mat33 primitive_orth_matrix(char centring_type) const {
    if (centring_type == 'P')
      return orth.mat;
    Mat33 c2p = rot_as_mat33(centred_to_primitive(centring_type));
    return orth.mat.multiply(c2p);
  }
};

} // namespace gemmi
#endif

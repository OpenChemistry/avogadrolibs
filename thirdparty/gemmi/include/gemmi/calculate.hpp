// Copyright 2017-2018 Global Phasing Ltd.
//
// Calculate various properties of the model.

#ifndef GEMMI_CALCULATE_HPP_
#define GEMMI_CALCULATE_HPP_

#include <array>
#include <algorithm>  // for std::min, std::minmax
#include "model.hpp"
#include "select.hpp"

namespace gemmi {

/// @brief Check if an object or any of its descendants contains hydrogen atoms.
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to check
/// @return True if hydrogen is present, false otherwise
template<class T> bool has_hydrogen(const T& obj) {
  for (const auto& child : obj.children())
    if (has_hydrogen(child))
      return true;
  return false;
}
template<> inline bool has_hydrogen(const Atom& atom) {
  return atom.is_hydrogen();
}

/// @brief Count atom sites in an object, optionally filtered by Selection.
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to count atoms in
/// @param sel Optional Selection filter; nullptr means all atoms
/// @return Number of matching atom sites
template<class T> size_t count_atom_sites(const T& obj, const Selection* sel=nullptr) {
  size_t sum = 0;
  if (!sel || sel->matches(obj))
    for (const auto& child : obj.children())
      sum += count_atom_sites(child, sel);
  return sum;
}
template<> inline size_t count_atom_sites(const Atom& atom, const Selection* sel) {
  return (!sel || sel->matches(atom)) ? 1 : 0;
}

/// @brief Sum occupancies in an object, optionally filtered by Selection.
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to sum occupancies in
/// @param sel Optional Selection filter; nullptr means all atoms
/// @return Sum of occupancies for matching atoms
template<class T> double count_occupancies(const T& obj, const Selection* sel=nullptr) {
  double sum = 0;
  if (!sel || sel->matches(obj))
    for (const auto& child : obj.children())
        sum += count_occupancies(child, sel);
  return sum;
}
template<> inline double count_occupancies(const Atom& atom, const Selection* sel) {
  return (!sel || sel->matches(atom)) ? atom.occ : 0;
}

/// @brief Calculate total mass in atomic mass units for an object.
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to calculate mass for
/// @return Total mass in atomic mass units (accounting for occupancy)
template<class T> double calculate_mass(const T& obj) {
  double sum = 0;
  for (const auto& child : obj.children())
    sum += calculate_mass(child);
  return sum;
}
template<> inline double calculate_mass(const Atom& atom) {
  return atom.occ * atom.element.weight();
}

/// @brief Result of center-of-mass calculation.
struct CenterOfMass {
  /// Sum of mass-weighted positions
  Position weighted_sum;
  /// Total mass
  double mass;
  /// @brief Get center-of-mass position.
  /// @return Mass-weighted centroid (weighted_sum / mass)
  Position get() const { return Position(weighted_sum / mass); }
};

/// @brief Calculate the center of mass (mass-weighted centroid).
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to calculate center of mass for
/// @return CenterOfMass with weighted_sum and total mass
template<class T> CenterOfMass calculate_center_of_mass(const T& obj) {
  CenterOfMass total{{}, 0.};
  for (const auto& child : obj.children()) {
    CenterOfMass part = calculate_center_of_mass(child);
    total = {total.weighted_sum + part.weighted_sum, total.mass + part.mass};
  }
  return total;
}
template<> inline CenterOfMass calculate_center_of_mass(const Atom& atom) {
  double w_mass = atom.element.weight() * atom.occ;
  return CenterOfMass{Position(atom.pos * w_mass), w_mass};
}

/// @brief Calculate min and max isotropic B-factors in an object.
/// @tparam T Type of object (Model, Chain, Residue, Atom, etc.)
/// @param obj Object to scan
/// @return Pair of (min_B, max_B)
template<class T> std::pair<float,float> calculate_b_iso_range(const T& obj) {
  std::pair<float, float> range{INFINITY, -INFINITY};
  for (const auto& child : obj.children()) {
    auto r = calculate_b_iso_range(child);
    range.first = std::min(range.first, r.first);
    range.second = std::max(range.second, r.second);
  }
  return range;
}
template<> inline std::pair<float,float> calculate_b_iso_range(const Atom& atom) {
  return {atom.b_iso, atom.b_iso};
}

/// @brief Calculate min and max B-factors from anisotropic B-tensors.
/// Uses min/max eigenvalues of anisotropic B-tensor, or B_iso if B-factor is isotropic.
/// @param model Model to scan
/// @return Pair of (min_eigenvalue * u_to_b(), max_eigenvalue * u_to_b())
inline std::pair<double, double> calculate_b_aniso_range(const Model& model) {
  std::pair<double, double> range{INFINITY, -INFINITY};
  for (const Chain& chain : model.chains)
    for (const Residue& residue : chain.residues)
      for (const Atom& atom : residue.atoms) {
        if (atom.occ == 0)
          continue;
        if (atom.aniso.nonzero()) {
          std::array<double,3> eig = atom.aniso.calculate_eigenvalues();
          auto u = std::minmax({eig[0], eig[1], eig[2]});
          range.first = std::min(range.first, u.first * u_to_b());
          range.second = std::max(range.second, u.second * u_to_b());
        } else {
          range.first = std::min(range.first, (double) atom.b_iso);
          range.second = std::max(range.second, (double) atom.b_iso);
        }
      }
  return range;
}


/// @brief Expand an axis-aligned bounding box to include all atoms in obj.
/// @tparam T Type supporting children() iteration (Model, Chain, Residue, or Atom).
/// @param obj Object whose atom positions are added to the box.
/// @param box Bounding box to expand in-place.
template<class T> void expand_box(const T& obj, Box<Position>& box) {
  for (const auto& child : obj.children())
    expand_box(child, box);
}
template<> inline void expand_box(const Atom& atom, Box<Position>& box) {
  box.extend(atom.pos);
}

/// @brief Calculate axis-aligned bounding box in Cartesian space.
/// @note NCS is not taken into account here (cf. NeighborSearch::set_bounding_cell())
/// @param st Structure to scan
/// @param margin Optional margin to add around the box
/// @return Axis-aligned bounding box
inline Box<Position> calculate_box(const Structure& st, double margin=0.) {
  Box<Position> box;
  expand_box(st, box);
  if (margin != 0.)
    box.add_margin(margin);
  return box;
}

/// @brief Calculate bounding box in fractional coordinates.
/// @param st Structure to scan (must have a unit cell)
/// @param margin Optional margin in Cartesian space (converted to fractional)
/// @return Bounding box in fractional coordinates
/// @throws Fails with message if Structure has no unit cell
inline Box<Fractional> calculate_fractional_box(const Structure& st, double margin=0.) {
  if (!st.cell.is_crystal())
    fail("calculate_fractional_box(): Structure has no unit cell for fractionalization");
  Box<Fractional> box;
  for (const Model& model : st.models)
    for (const Chain& chain : model.chains)
      for (const Residue& res : chain.residues)
        for (const Atom& atom : res.atoms)
          box.extend(st.cell.fractionalize(atom.pos));
  if (margin != 0.)
    box.add_margins({margin * st.cell.ar, margin * st.cell.br, margin * st.cell.cr});
  return box;
}


/// @brief Calculate B_equiv from anisotropic B-tensor (or B_iso if isotropic).
/// @param atom Atom with (possibly anisotropic) B-factor
/// @return B_equiv = sqrt((sum_eigenvalues) / (sum_inverse_eigenvalues)) * u_to_b()
/// @par References
/// Merritt, E.A. (2011). Some B_eq are more equivalent than others.
/// Acta Cryst. A67, 512–516. https://doi.org/10.1107/S0108767311034350
inline double calculate_b_est(const Atom& atom) {
  auto eig = atom.aniso.calculate_eigenvalues();
  return u_to_b() * std::sqrt((eig[0] + eig[1] + eig[2]) /
                              (1/eig[0] + 1/eig[1] + 1/eig[2]));
}

/// @brief Calculate angle at p1 between vectors p1→p0 and p1→p2.
/// @param p0 First position
/// @param p1 Central position (vertex of the angle)
/// @param p2 Third position
/// @return Angle in radians
inline double calculate_angle(const Position& p0, const Position& p1,
                              const Position& p2) {
  return (p0 - p1).angle(p2 - p1);
}

/// @brief Calculate dihedral angle defined by four positions.
/// @param p0 First position
/// @param p1 Second position (on the bond axis)
/// @param p2 Third position (on the bond axis)
/// @param p3 Fourth position
/// @return Dihedral angle in radians, in the range [-π, π]
/// @note See discussion at https://stackoverflow.com/questions/20305272/
inline double calculate_dihedral(const Position& p0, const Position& p1,
                                 const Position& p2, const Position& p3) {
  Vec3 b0 = p1 - p0;
  Vec3 b1 = p2 - p1;
  Vec3 b2 = p3 - p2;
  Vec3 u = b1.cross(b0);
  Vec3 w = b2.cross(b1);
  double y = u.cross(w).dot(b1);
  double x = u.dot(w) * b1.length();
  return std::atan2(y, x);
}

/// @brief Calculate dihedral angle from four Atom pointers.
/// @param a First atom pointer
/// @param b Second atom pointer (on the bond axis)
/// @param c Third atom pointer (on the bond axis)
/// @param d Fourth atom pointer
/// @return Dihedral angle in radians (same range as atan2: [-π, π]), or NaN if any pointer is null
inline double calculate_dihedral_from_atoms(const Atom* a, const Atom* b,
                                            const Atom* c, const Atom* d) {
  if (a && b && c && d)
    return calculate_dihedral(a->pos, b->pos, c->pos, d->pos);
  return NAN;
}

/// @brief Calculate peptide bond ω dihedral angle.
/// ω is defined by atoms: Cα(i) - C(i) - N(i+1) - Cα(i+1)
/// @param res Current residue
/// @param next Next residue
/// @return Omega angle in radians, or NaN if atoms are missing
inline double calculate_omega(const Residue& res, const Residue& next) {
  return calculate_dihedral_from_atoms(res.get_ca(), res.get_c(),
                                       next.get_n(), next.get_ca());
}

/// @brief Check if a peptide bond is in cis configuration.
/// @param ca1 Cα atom of the current residue
/// @param c C atom of the current residue
/// @param n N atom of the next residue
/// @param ca2 Cα atom of the next residue
/// @param tolerance_deg Tolerance in degrees (absolute |ω| < tolerance indicates cis)
/// @return True if |ω| < tolerance_deg, false otherwise
inline bool is_peptide_bond_cis(const Atom* ca1, const Atom* c,
                                const Atom* n, const Atom* ca2,
                                double tolerance_deg) {
  double omega = calculate_dihedral_from_atoms(ca1, c, n, ca2);
  return std::fabs(omega) < rad(tolerance_deg);
}

/// @brief Calculate chiral volume (scalar triple product).
/// @param actr Central atom position (center of chirality)
/// @param a1 First substituent position
/// @param a2 Second substituent position
/// @param a3 Third substituent position
/// @return Scalar triple product: (a1-actr) · ((a2-actr) × (a3-actr))
inline double calculate_chiral_volume(const Position& actr, const Position& a1,
                                      const Position& a2, const Position& a3) {
  return (a1 - actr).dot((a2 - actr).cross(a3 - actr));
}

/// @brief Calculate Ramachandran dihedral angles φ (phi) and ψ (psi).
/// φ is defined by: C(i-1) - N(i) - Cα(i) - C(i)
/// ψ is defined by: N(i) - Cα(i) - C(i) - N(i+1)
/// @param prev Previous residue (nullptr if not available)
/// @param res Current residue
/// @param next Next residue (nullptr if not available)
/// @return Array [phi, psi] in radians; NaN values if flanking residues are missing or atoms not found
inline std::array<double, 2> calculate_phi_psi(const Residue* prev,
                                               const Residue& res,
                                               const Residue* next) {
  std::array<double, 2> phi_psi{{NAN, NAN}};
  if (prev || next) {
    const Atom* CA = res.get_ca();
    const Atom* C = res.get_c();
    const Atom* N = res.get_n();
    if (prev)
      phi_psi[0] = calculate_dihedral_from_atoms(prev->get_c(), N, CA, C);
    if (next)
      phi_psi[1] = calculate_dihedral_from_atoms(N, CA, C, next->get_n());
  }
  return phi_psi;
}

/// @brief Find the least-squares plane through a set of atoms.
/// @param atoms Vector of atom pointers
/// @return Array [a, b, c, d] representing plane equation ax + by + cz = d
/// @note All atoms must have non-zero occupancy to be included
GEMMI_DLL std::array<double, 4> find_best_plane(const std::vector<Atom*>& atoms);

/// @brief Calculate signed distance from a point to a plane.
/// @param pos Position of the point
/// @param coeff Plane coefficients [a, b, c, d] from ax + by + cz = d
/// @return Signed distance from pos to plane
inline double get_distance_from_plane(const Position& pos,
                                      const std::array<double, 4>& coeff) {
  return coeff[0] * pos.x + coeff[1] * pos.y + coeff[2] * pos.z + coeff[3];
}

/// @brief Parse a crystallographic triplet string into an FTransform.
/// @param s CIF triplet string (e.g., "x,y,z" or "-x+1/2,-y,z")
/// @return FTransform representing the fractional transformation
GEMMI_DLL FTransform parse_triplet_as_ftransform(const std::string& s);

/// @brief Calculate the anisotropic U tensor at a position from TLS group parameters.
/// @param tls TLS group parameters (T, L, S matrices)
/// @param pos Position where U is evaluated
/// @return 3×3 symmetric matrix U at the given position
GEMMI_DLL SMat33<double> calculate_u_from_tls(const TlsGroup& tls, const Position& pos);

} // namespace gemmi
#endif

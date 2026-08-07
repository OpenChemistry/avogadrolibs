/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_CONSTRAINT_H
#define AVOGADRO_CORE_CONSTRAINT_H

#include "avogadrocoreexport.h"

#include <avogadro/core/avogadrocore.h>
#include <tuple>

namespace Avogadro {
namespace Core {

/**
 * @class Constraint constraint.h <avogadro/core/constraint.h>
 * @brief Constraints for optimization / dynamics
 * @author Geoffrey R. Hutchison
 *
 * This class represents a distance, angle, or torsional constraint / restraint
 * during optimization or dynamics. More technically, these are implemented as
 * stiff harmonic oscillators restraining a particular atom set towards the
 * value.
 *
 * Distances are stored in Angstrom and angles / torsions in degrees, matching
 * what the user sees in the property tables and constraint dialog. Energy
 * calculators convert angular values to radians internally, so the angular
 * force constants are in kJ/mol/radian^2.
 */
class AVOGADROCORE_EXPORT Constraint
{
public:
  /** Default force constant for distance restraints, in kJ/mol/Angstrom^2 */
  static constexpr Real DefaultDistanceK = 41840.0;
  /** Default force constant for angular restraints, in kJ/mol/radian^2 */
  static constexpr Real DefaultAngularK = 10000.0;

  enum Type
  {
    None = 0,
    DistanceConstraint,
    AngleConstraint,
    TorsionConstraint,
    OutOfPlaneConstraint,
    UnknownConstraint
  };

  /**
   * Constructor, results in a zero distance constraint
   * @param a Atom index of the first atom of the constraint
   * @param b Atom index of the second atom of the constraint
   * @param c Atom index of the third atom (for angles or torsions) or MaxIndex
   * @param d Atom index of the fourth atom (for torsion constraints) or
   * MaxIndex
   * @param value The value of the constraint, either Angstrom for distance
   * or degrees for angles and torsions
   */
  Constraint(Index a, Index b, Index c = MaxIndex, Index d = MaxIndex,
             Real value = 0.0)
    : m_aIndex(a), m_bIndex(b), m_cIndex(c), m_dIndex(d), m_value(value)
  {
  }

  /** Set the constraint
   * @param a Atom index of the first atom of the constraint
   * @param b Atom index of the second atom of the constraint
   * @param c Atom index of the third atom (for angles or torsions) or MaxIndex
   * @param d Atom index of the fourth atom (for torsion constraints) or
   * MaxIndex
   * @param value The value of the constraint, either Angstrom for distance
   * or degrees for angles and torsions
   */
  void set(Index a, Index b, Index c = MaxIndex, Index d = MaxIndex,
           Real value = 0.0)
  {
    m_aIndex = a;
    m_bIndex = b;
    m_cIndex = c;
    m_dIndex = d;
    m_value = value;

    // The atom indices decide the inferred type, so a cached guess is stale
    // now -- leaving it would keep, e.g., a distance force constant on what
    // is now a torsion. A type set explicitly via setType() is kept.
    if (!m_typeExplicit)
      m_type = None;
  }

  /**
   * Set the constraint value (distance, angle, dihedral)
   * @param value The value of the constraint, either Angstrom for distance
   * or degrees for angles and torsions
   */
  void setValue(Real value) { m_value = value; }

  /**
   * @return the constraint value
   */
  Real value() const { return m_value; }

  /**
   * @return the atoms in the constraint as a tuple
   */
  std::tuple<Index, Index, Index, Index> atoms() const
  {
    return std::make_tuple(m_aIndex, m_bIndex, m_cIndex, m_dIndex);
  }

  /**
   * @return the atom index from the constraint or MaxIndex
   */
  Index aIndex() const { return m_aIndex; }
  Index bIndex() const { return m_bIndex; }
  Index cIndex() const { return m_cIndex; }
  Index dIndex() const { return m_dIndex; }

  /**
   * @return the harmonic force constant, either kJ/mol/Angstrom^2 for a
   * distance restraint or kJ/mol/radian^2 for an angular one. If no force
   * constant has been set explicitly, a type-appropriate default is used --
   * the two have different units and cannot share a value.
   */
  Real k() const
  {
    if (m_kSet)
      return m_k;

    return (type() == DistanceConstraint) ? DefaultDistanceK : DefaultAngularK;
  }

  void setK(Real k)
  {
    m_k = k;
    m_kSet = true;
  }

  /**
   * @return the type of constraint
   */
  Constraint::Type type() const
  {
    if (m_type != None)
      return m_type;

    if (m_cIndex == MaxIndex && m_dIndex == MaxIndex)
      m_type = DistanceConstraint;
    else if (m_dIndex == MaxIndex)
      m_type = AngleConstraint;
    else if (m_dIndex != MaxIndex)
      m_type = TorsionConstraint;
    else
      m_type = UnknownConstraint;

    return m_type;
  }

  /**
   * Set the type of constraint. An explicit type survives later set() calls,
   * since it cannot always be inferred from the atom indices -- an
   * out-of-plane constraint has the same four indices as a torsion. Pass None
   * to go back to inferring the type from the indices.
   * @param type The type of constraint
   */
  void setType(Constraint::Type type) const
  {
    m_type = type;
    m_typeExplicit = (type != None);
  }

protected:
  Index m_aIndex = MaxIndex;
  Index m_bIndex = MaxIndex;
  Index m_cIndex = MaxIndex;
  Index m_dIndex = MaxIndex;
  Real m_value = 0.0;
  Real m_k = DefaultDistanceK;            // units depend on the constraint type
  bool m_kSet = false;                    // true once setK() has been called
  mutable Constraint::Type m_type = None; // cached type, initialized to None
  mutable bool m_typeExplicit = false;    // true once setType() has been called
};

} // End namespace Core
} // End namespace Avogadro

#endif // AVOGADRO_CORE_CONSTRAINT_H

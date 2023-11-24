/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_RESIDUE_H
#define AVOGADRO_CORE_RESIDUE_H

#include "avogadrocoreexport.h"

#include "avogadrocore.h"

#include <map>
#include <string>

#include "array.h"
#include "bond.h"
#include "vector.h"

namespace Avogadro {
namespace Core {

class Atom;
class Molecule;

/**
 * @class Residue residue.h <avogadro/core/residue.h>
 * @brief The Residue class represents a chemical residue, used commonly in the
 * PDB format.
 */
class AVOGADROCORE_EXPORT Residue
{
public:
  /** Type for atom name map. */
  typedef std::map<std::string, Atom> AtomNameMap;

  // using codes from MMTF specification
  // https://github.com/rcsb/mmtf/blob/master/spec.md#secstructlist
  enum SecondaryStructure
  {
    piHelix = 0,    // DSSP "I"
    bend = 1,       // DSSP "S"
    alphaHelix = 2, // DSSP "H"
    betaSheet = 3,  // DSSP "E"
    helix310 = 4,   // DSSP "G"
    betaBridge = 5, // DSSP "B"
    turn = 6,       // DSSP "T"
    coil = 7,       // DSSP "C"
    maybeBeta = -3, // potential beta strand
    undefined = -1
  };

  /** Creates a new, empty residue. */
  Residue();
  Residue(std::string& name);
  Residue(std::string& name, Index& number);
  Residue(std::string& name, Index& number, char& id);

  Residue(const Residue& other);

  Residue& operator=(Residue other);

  virtual ~Residue();

  inline std::string residueName() const { return m_residueName; }

  inline void setResidueName(std::string& name) { m_residueName = name; }

  inline Index residueId() const { return m_residueId; }

  inline void setResidueId(Index& number) { m_residueId = number; }

  inline char chainId() const { return m_chainId; }

  inline void setChainId(const char& id) { m_chainId = id; }

  inline SecondaryStructure secondaryStructure() const
  {
    return m_secondaryStructure;
  }

  inline void setSecondaryStructure(const SecondaryStructure& ss)
  {
    m_secondaryStructure = ss;
  }

  /** Adds an atom to the residue class */
  void addResidueAtom(const std::string& name, const Atom& atom);

  /** \return a vector containing the atoms added to the residue */
  std::vector<Atom> residueAtoms() const;

  /** \return the atom map for the residue */
  AtomNameMap& atomNameMap() { return m_atomNameMap; }

  /** Sets bonds to atoms in the residue based on data from residuedata header
   */
  void resolveResidueBonds(Molecule& mol);

  /**
   * \return the atom with the name specified (e.g., "CA")
   */
  Atom getAtomByName(std::string name) const;
  /**
   * \return the atomic number of the atom with the name specified (e.g., "CA" =
   * "C")
   */
  int getAtomicNumber(std::string name) const;

  /**
   * \return the name of @p atom or an empty string if not in this residue
   */
  std::string getAtomName(const Atom atom) const;

  /**
   * \return the name of atom @p index or an empty string if not in this residue
   */
  std::string getAtomName(const Index index) const;

  bool hasAtomByIndex(Index index) const;
  /** Set whether this residue is a "HET" / "HETATOM" ligand
   */
  void setHeterogen(bool heterogen) { m_heterogen = heterogen; }

  /** \return is this residue a heterogen (HET / HETATM)
   */
  bool isHeterogen() const { return m_heterogen; }

  /** Set a custom color for this residue
   */
  void setColor(const Vector3ub color);

  /** \return the color set for this residue, or a default from the chain id
   */
  Vector3ub color() const;

protected:
  std::string m_residueName;
  Index m_residueId;
  char m_chainId;
  AtomNameMap m_atomNameMap;
  bool m_heterogen;
  Vector3ub m_color;
  bool m_customColorSet;
  SecondaryStructure m_secondaryStructure;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_RESIDUE_H

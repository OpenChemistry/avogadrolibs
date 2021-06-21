/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CORE_RESIDUE_H
#define AVOGADRO_CORE_RESIDUE_H

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

  /** Creates a new, empty residue. */
  Residue();
  Residue(std::string& name);
  Residue(std::string& name, Index& number);
  Residue(std::string& name, Index& number, char& id);

  Residue(const Residue& other);

  Residue& operator=(Residue other);

  virtual ~Residue();

  inline std::string residueName() { return m_residueName; }

  inline void setResidueName(std::string& name) { m_residueName = name; }

  inline Index residueId() { return m_residueId; }

  inline void setResidueId(Index& number) { m_residueId = number; }

  inline char chainId() { return m_chainId; }

  inline void setChainId(char& id) { m_chainId = id; }

  /** Adds an atom to the residue class */
  void addResidueAtom(std::string& name, Atom& atom);

  /** \return a vector containing the atoms added to the residue */
  std::vector<Atom> residueAtoms();

  /** Sets bonds to atoms in the residue based on data from residuedata header
   */
  void resolveResidueBonds(Molecule& mol);

  Atom getAtomByName(std::string name);

  int getAtomicNumber(std::string name);

  void setHeterogen(bool heterogen) { m_heterogen = heterogen;}

  /** \return is this residue a heterogen (HET / HETATM)
   */
  bool isHeterogen() { return m_heterogen; }

protected:
  std::string m_residueName;
  Index m_residueId;
  char m_chainId;
  AtomNameMap m_atomNameMap;
  bool m_heterogen;
};

} // namespace Core
} // namespace Avogadro

#endif // AVOGADRO_CORE_RESIDUE_H

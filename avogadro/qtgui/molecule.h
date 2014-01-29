/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_MOLECULE_H
#define AVOGADRO_QTGUI_MOLECULE_H

#include "avogadroqtguiexport.h"

#include <avogadro/core/molecule.h>

#include <QtCore/QObject>

namespace Avogadro {
namespace QtGui {

class Mesh;

/**
 * @class Molecule molecule.h <avogadro/qtgui/molecule.h>
 * @brief A QObject derived molecule object with signals/slots.
 */

class AVOGADROQTGUI_EXPORT Molecule : public QObject, public Core::Molecule
{
  Q_OBJECT
public:
  Molecule(QObject *parent_ = 0);
  ~Molecule();
  /** copy constructor */
  Molecule(const Molecule &other);

  /** Assignment operator */
  Molecule& operator=(const Molecule& other);

  /** Assignment operator to copy data from base instance */
  Molecule& operator=(const Core::Molecule& other);

  /** \enum Enumeration of change types that can be given. */
  enum MoleculeChange {
    /** Useful for initializing MoleculeChange variables. */
    NoChange = 0x0,
    /** Object types that can be changed. */
    Atoms = 0x01,
    Bonds = 0x02,
    UnitCell = 0x04,
    /** Operations that can affect the above types. */
    Added    = 0x1024,
    Removed  = 0x2048,
    Modified = 0x4096
  };
  Q_DECLARE_FLAGS(MoleculeChanges, MoleculeChange)

  /**
   * Add an atom with @p atomicNumber to the molecule.
   * @return The atom created.
   */
  Core::Atom addAtom(unsigned char atomicNumber) AVO_OVERRIDE;

  /**
   * Add an atom with @p atomicNumber and @p uniqueId to the molecule.
   * @return The atom created. This can be invalid if the unique ID was already
   * in use.
   */
  virtual Core::Atom addAtom(unsigned char atomicNumber, Index uniqueId);

  /**
   * @brief Remove the specified atom from the molecule.
   * @param index The index of the atom to be removed.
   * @return True on success, false if the atom was not found.
   */
  bool removeAtom(Index index) AVO_OVERRIDE;

  /**
   * @brief Remove the specified atom from the molecule.
   * @param atom The atom to be removed.
   * @return True on success, false if the atom was not found.
   * @overload
   */
  bool removeAtom(const Core::Atom &atom) AVO_OVERRIDE;

  /**
   * @brief Get the atom referenced by the @p uniqueId, the isValid method
   * should be queried to ensure the id still referenced a valid atom.
   * @param uniqueId The unique identifier for the atom.
   * @return An Atom object, check it is valid before using it.
   */
  Core::Atom atomByUniqueId(Index uniqueId);

  /**
   * @brief Get the unique ID of the atom, this will uniquely reference the atom
   * as long as it exists.
   * @param atom The atom to obtain the unique ID of.
   * @return The unique identifier for the atom, MaxIndex if the atom is invalid
   * or does not belong to this molecule.
   */
  Index atomUniqueId(const Core::Atom &atom) const;

  /**
   * @brief Add a bond between the specified atoms.
   * @param a The first atom in the bond.
   * @param b The second atom in the bond.
   * @param bondOrder The order of the bond.
   * @return The bond created.
   */
  Core::Bond addBond(const Core::Atom &a, const Core::Atom &b,
                     unsigned char bondOrder = 1) AVO_OVERRIDE;

  /**
   * @brief Add a bond between the specified atoms.
   * @param a The first atom in the bond.
   * @param b The second atom in the bond.
   * @param bondOrder The order of the bond.
   * @param uniqueId The unique ID to use for the bond.
   * @return The bond created. This can be invalid if the unique ID was already
   * in use.
   */
  virtual Core::Bond addBond(const Core::Atom &a, const Core::Atom &b,
                             unsigned char bondOrder, Index uniqueId);

  /**
   * @brief Remove the specified bond.
   * @param index The index of the bond to be removed.
   * @return True on success, false if the bond was not found.
   */
  bool removeBond(Index index) AVO_OVERRIDE;

  /**
   * @brief Remove the specified bond.
   * @param bond The bond to be removed.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  bool removeBond(const Core::Bond &bond) AVO_OVERRIDE;

  /**
   * @brief Remove the specified bond.
   * @param a One atom in the bond.
   * @param b The other atom in the bond.
   * @return True on success, false if the bond was not found.
   * @overload
   */
  bool removeBond(const Core::Atom &a, const Core::Atom &b) AVO_OVERRIDE;

  /**
   * @brief Get the bond referenced by the @p uniqueId, the isValid method
   * should be queried to ensure the id still referenced a valid bond.
   * @param uniqueId The unique identifier for the bond.
   * @return A Bond object, check it is valid before using it.
   */
  Core::Bond bondByUniqueId(Index uniqueId);

  /**
   * @brief Get the unique ID of the bond, this will uniquely reference the bond
   * as long as it exists.
   * @param bond The bond to obtain the unique ID of.
   * @return The unique identifier for the bond, MaxIndex if the bond is invalid
   * or does not belong to this molecule.
   */
  Index bondUniqueId(const Core::Bond &bond) const;

public slots:
  /**
   * @brief Force the molecule to emit the changed() signal.
   * @param change See changed().
   */
  void emitChanged(unsigned int change);

signals:
  /**
   * @brief Indicates that the molecule has changed.
   * @param change Use the MoleculeChange enum to check what has changed.
   *
   * The @p change variable indicates what has changed, i.e. if
   * change & Atoms == true then atoms were changed in some way, and if
   * change & Removed == true then one or more atoms were removed.
   */
  void changed(unsigned int change);

private:
  std::vector<Index> m_atomUniqueIds;
  std::vector<Index> m_bondUniqueIds;

  Index findAtomUniqueId(Index index) const;
  Index findBondUniqueId(Index index) const;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(Molecule::MoleculeChanges)

} // end QtGui namespace
} // end Avogadro namespace

#endif // AVOGADRO_QTGUI_MOLECULE_H

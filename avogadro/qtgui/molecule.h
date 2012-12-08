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

class AVOGADROQTGUI_EXPORT Molecule : public QObject, public Core::Molecule
{
  Q_OBJECT
public:
  Molecule(QObject *parent_ = 0);
  ~Molecule();

  /*! \enum Enumeration of change types that can be given. */
  enum MoleculeChange {
    /// Object types that can be changed.
    Atoms = 0x01,
    Bonds = 0x02,
    /// Operations that can affect the above types.
    Added    = 0x1024,
    Removed  = 0x2048,
    Modified = 0x4096
  };

  /*!
   * Add an atom with \p atomicNumber to the molecule.
   * \return The atom created.
   */
  Core::Atom addAtom(unsigned char atomicNumber);
  //Atom atom(size_t index) const;

  /*!
   * \brief removeAtom
   * \param index The index of the atom to be removed.
   * \return True on success, false if the atom was not found.
   */
  bool removeAtom(size_t index);
  bool removeAtom(const Core::Atom &atom);

  /*!
   * \brief Add a bond between the specified atoms.
   * \param a The first atom in the bond.
   * \param b The second atom in the bond.
   * \param bondOrder The order of the bond.
   * \return The bond created.
   */
  Core::Bond addBond(const Core::Atom &a, const Core::Atom &b,
                     unsigned char bondOrder = 1);

  /*!
   * \brief Remove the specified bond.
   * \param index The index of the bond to be remove.
   * \return True on succes, false if the bond was not found.
   */
  bool removeBond(size_t index);
  bool removeBond(const Core::Bond &bond);
  bool removeBond(const Core::Atom &a, const Core::Atom &b);
  //Bond bond(size_t index) const;
  //Bond bond(const Atom &a, const Atom &b) const;

signals:
  /*!
   * \brief Indicates that the molecule has changed.
   * \param change Use the MoleculeChange enum to check what has changed.
   *
   * The \p change variable indicates what has changed, i.e. if
   * change & Atoms == true then atoms were changed in some way, and if
   * change & Removed == true then one or more atoms were removed.
   */
  void changed(unsigned int change);

private:
  std::vector<int> m_atomUniqueIds;
  std::vector<int> m_bondUniqueIds;

  int findAtomUniqueId(size_t index) const;
  int findBondUniqueId(size_t index) const;
};

} // end QtGui namespace
} // end Avogadro namespace

#endif // AVOGADRO_QTGUI_MOLECULE_H

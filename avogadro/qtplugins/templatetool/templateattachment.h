/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_TEMPLATEATTACHMENT_H
#define AVOGADRO_QTPLUGINS_TEMPLATEATTACHMENT_H

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

#include <vector>

namespace Avogadro {
namespace Core {
class Molecule;
}
namespace QtPlugins {

/**
 * Ligand templates mark the metal center with a dummy atom. These helpers are
 * shared by the tool and the tool widget so both agree on which dummy atom a
 * template attaches through, and on how many attachment points it offers.
 */

/**
 * @return the index of the dummy atom @a templateMolecule attaches through, or
 * MaxIndex if it has none. Haptic ligands carry more than one dummy atom, in
 * which case the one furthest from the centroid of the carbons is used.
 */
Index templateAttachmentDummy(const Core::Molecule& templateMolecule);

/**
 * @return the atoms bonded to @a dummyIndex, i.e. the donor atoms that will be
 * bonded to the metal center. Empty if @a dummyIndex is not a valid atom.
 */
std::vector<Index> templateAttachmentPoints(
  const Core::Molecule& templateMolecule, Index dummyIndex);

/**
 * @return the number of attachment points offered by the CJSON template in
 * @a fileName, i.e. its denticity, or 0 if the file cannot be read.
 */
int templateDenticity(const QString& fileName);

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_TEMPLATEATTACHMENT_H

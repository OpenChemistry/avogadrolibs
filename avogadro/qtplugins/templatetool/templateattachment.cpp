/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "templateattachment.h"

#include <avogadro/core/molecule.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/cjsonformat.h>

#include <QtCore/QFile>
#include <QtCore/QTextStream>

namespace Avogadro {
namespace QtPlugins {

Index templateAttachmentDummy(const Core::Molecule& templateMolecule)
{
  // For haptic ligands we have more than one dummy atom, so we pick the one
  // furthest from the centroid of the carbon atoms.
  Vector3 centroid(0.0, 0.0, 0.0);
  unsigned carbonCount = 0;
  for (Index i = 0; i < templateMolecule.atomCount(); ++i) {
    if (templateMolecule.atomicNumber(i) == 6) {
      carbonCount++;
      centroid += templateMolecule.atomPosition3d(i);
    }
  }
  if (carbonCount > 1)
    centroid = centroid / carbonCount;

  Index dummyIndex = MaxIndex;
  Real maxDistance = 0.0;
  for (Index i = 0; i < templateMolecule.atomCount(); ++i) {
    if (templateMolecule.atomicNumber(i) != 0)
      continue;

    Vector3 delta = templateMolecule.atomPosition3d(i) - centroid;
    if (dummyIndex != MaxIndex && delta.squaredNorm() < maxDistance)
      continue; // too close to the centroid

    maxDistance = delta.squaredNorm();
    dummyIndex = i;
  }

  return dummyIndex;
}

std::vector<Index> templateAttachmentPoints(
  const Core::Molecule& templateMolecule, Index dummyIndex)
{
  std::vector<Index> attachmentPoints;
  if (dummyIndex == MaxIndex || dummyIndex >= templateMolecule.atomCount())
    return attachmentPoints;

  for (const Core::Bond* bond : templateMolecule.bonds(dummyIndex))
    attachmentPoints.push_back(bond->getOtherAtom(dummyIndex).index());

  return attachmentPoints;
}

int templateDenticity(const QString& fileName)
{
  QFile templateFile(fileName);
  if (!templateFile.open(QFile::ReadOnly | QFile::Text))
    return 0;

  QTextStream templateStream(&templateFile);
  Core::Molecule templateMolecule;
  Io::CjsonFormat format;
  if (!format.readString(templateStream.readAll().toStdString(),
                         templateMolecule))
    return 0;

  return static_cast<int>(
    templateAttachmentPoints(templateMolecule,
                             templateAttachmentDummy(templateMolecule))
      .size());
}

} // namespace QtPlugins
} // namespace Avogadro

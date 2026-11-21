/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "centroid.h"

#include <avogadro/qtgui/commandregistry.h>
#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <QAction>

namespace Avogadro::QtPlugins {

using Core::Array;
using Core::Elements;

Centroid::Centroid(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_),
    m_centroidAction(new QAction(tr("Add Centroid"), this)),
    m_comAction(new QAction(tr("Add Center of Mass"), this)),
    m_normalAction(
      new QAction(tr("Add Perpendicular",
                     "add a point normal to the plane of the molecule"),
                  this))
{
  m_centroidAction->setProperty("menu priority", 190);
  m_comAction->setProperty("menu priority", 180);
  m_normalAction->setProperty("menu priority", 170);

  connect(m_centroidAction, SIGNAL(triggered()), SLOT(addCentroid()));
  connect(m_comAction, SIGNAL(triggered()), SLOT(addCenterOfMass()));
  connect(m_normalAction, SIGNAL(triggered()), SLOT(normal()));

  registerCentroidCommands();
}

QList<QAction*> Centroid::actions() const
{
  QList<QAction*> result;
  return result << m_centroidAction << m_comAction << m_normalAction;
}

QStringList Centroid::menuPath(QAction*) const
{
  return QStringList() << tr("&Build");
}

void Centroid::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
}

void Centroid::addCentroid()
{
  Index newIndex = 0;
  Vector3 newPos(0.0, 0.0, 0.0);
  computeCentroid(newIndex, newPos);
}

bool Centroid::computeCentroid(Index& newIndex, Vector3& newPos, QString* error)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0) {
    if (error)
      *error = tr("No molecule");
    return false;
  }

  Vector3 center(0.0, 0.0, 0.0);
  Index count = 0;
  bool hasSelection = !m_molecule->isSelectionEmpty();
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (hasSelection && !m_molecule->atomSelected(i))
      continue;
    // don't count dummy atoms
    if (m_molecule->atomicNumber(i) == 0)
      continue;

    center += m_molecule->atomPosition3d(i);
    ++count;
  }
  if (count == 0) {
    if (error)
      *error = tr("No non-dummy atoms found to compute centroid.");
    return false;
  }
  center /= count;

  auto atom = m_molecule->undoMolecule()->addAtom(0, center);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
  newIndex = atom.index();
  newPos = center;
  return true;
}

void Centroid::addCenterOfMass()
{
  Index newIndex = 0;
  Vector3 newPos(0.0, 0.0, 0.0);
  computeCenterOfMass(newIndex, newPos);
}

bool Centroid::computeCenterOfMass(Index& newIndex, Vector3& newPos,
                                   QString* error)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0) {
    if (error)
      *error = tr("No molecule");
    return false;
  }

  Vector3 center(0.0, 0.0, 0.0);
  Real totalMass = 0.0;
  Index count = 0;
  bool hasSelection = !m_molecule->isSelectionEmpty();

  // we have to first find the centroid
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (hasSelection && !m_molecule->atomSelected(i))
      continue;
    // skip it if it's a dummy atom
    if (m_molecule->atomicNumber(i) == 0)
      continue;

    Real mass = Elements::mass(m_molecule->atomicNumber(i));
    if (m_molecule->isotope(i) > 0)
      mass = Elements::isotopeMass(m_molecule->atomicNumber(i),
                                   m_molecule->isotope(i));
    center += m_molecule->atomPosition3d(i) * mass;

    totalMass += mass;
    ++count;
  }
  if (count == 0 || totalMass <= 0.0) {
    if (error)
      *error = tr("No non-dummy atoms found to compute center of mass.");
    return false;
  }
  center /= totalMass;

  auto atom = m_molecule->undoMolecule()->addAtom(0, center);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
  newIndex = atom.index();
  newPos = center;
  return true;
}

void Centroid::normal()
{
  Index newIndex = 0;
  Vector3 newPos(0.0, 0.0, 0.0);
  computeNormal(newIndex, newPos);
}

bool Centroid::computeNormal(Index& newIndex, Vector3& newPos, QString* error)
{
  if (m_molecule == nullptr || m_molecule->atomCount() == 0) {
    if (error)
      *error = tr("No molecule");
    return false;
  }

  Array<Vector3> points;
  bool hasSelection = !m_molecule->isSelectionEmpty();
  for (Index i = 0; i < m_molecule->atomCount(); ++i) {
    if (hasSelection && !m_molecule->atomSelected(i))
      continue;
    if (m_molecule->atomicNumber(i) == 0)
      continue;

    points.push_back(m_molecule->atomPosition3d(i));
  }

  if (points.size() < 3) {
    if (error) {
      if (points.empty())
        *error = tr("No non-dummy atoms found to compute perpendicular point.");
      else
        *error = tr("At least three non-dummy atoms are required to compute a "
                    "best-fit plane.");
    }
    return false;
  }

  auto pair = m_molecule->bestFitPlane(points);
  newPos = pair.second * 2.0 + pair.first;

  auto atom = m_molecule->undoMolecule()->addAtom(0, newPos);
  m_molecule->emitChanged(QtGui::Molecule::Atoms | QtGui::Molecule::Added);
  newIndex = atom.index();
  return true;
}

void Centroid::registerCentroidCommands()
{
  QtGui::CommandSpec addCentroid;
  addCentroid.name = "addCentroid";
  addCentroid.description =
    tr("Add a dummy atom at the geometric center of the "
       "molecule or the selected atoms.");
  addCentroid.needsMolecule = true;
  addCentroid.handler = [this](const QtGui::CommandArguments&) {
    Index newIndex = 0;
    Vector3 newPos(0.0, 0.0, 0.0);
    QString error;
    if (!computeCentroid(newIndex, newPos, &error)) {
      emit commandFailed(error);
      return;
    }
    QVariantMap result;
    result["index"] = static_cast<qlonglong>(newIndex);
    QVariantList posList;
    posList << newPos.x() << newPos.y() << newPos.z();
    result["position"] = posList;
    emit commandFinished(QString(), result);
  };
  commandRegistry().add(std::move(addCentroid));

  QtGui::CommandSpec addCenterOfMass;
  addCenterOfMass.name = "addCenterOfMass";
  addCenterOfMass.description =
    tr("Add a dummy atom at the center of mass of the "
       "molecule or the selected atoms.");
  addCenterOfMass.needsMolecule = true;
  addCenterOfMass.handler = [this](const QtGui::CommandArguments&) {
    Index newIndex = 0;
    Vector3 newPos(0.0, 0.0, 0.0);
    QString error;
    if (!computeCenterOfMass(newIndex, newPos, &error)) {
      emit commandFailed(error);
      return;
    }
    QVariantMap result;
    result["index"] = static_cast<qlonglong>(newIndex);
    QVariantList posList;
    posList << newPos.x() << newPos.y() << newPos.z();
    result["position"] = posList;
    emit commandFinished(QString(), result);
  };
  commandRegistry().add(std::move(addCenterOfMass));

  QtGui::CommandSpec addPerpendicular;
  addPerpendicular.name = "addPerpendicular";
  addPerpendicular.description =
    tr("Add a dummy atom perpendicular to the plane of the "
       "molecule or the selected atoms.");
  addPerpendicular.needsMolecule = true;
  addPerpendicular.handler = [this](const QtGui::CommandArguments&) {
    Index newIndex = 0;
    Vector3 newPos(0.0, 0.0, 0.0);
    QString error;
    if (!computeNormal(newIndex, newPos, &error)) {
      emit commandFailed(error);
      return;
    }
    QVariantMap result;
    result["index"] = static_cast<qlonglong>(newIndex);
    QVariantList posList;
    posList << newPos.x() << newPos.y() << newPos.z();
    result["position"] = posList;
    emit commandFinished(QString(), result);
  };
  commandRegistry().add(std::move(addPerpendicular));
}

bool Centroid::handleCommand(const QString& command,
                             [[maybe_unused]] const QVariantMap& options)
{
  return commandRegistry().handle(command, options, m_molecule);
}

} // namespace Avogadro::QtPlugins

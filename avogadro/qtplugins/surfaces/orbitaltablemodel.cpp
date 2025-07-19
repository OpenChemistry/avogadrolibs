/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orbitaltablemodel.h"
#include "orbitalwidget.h"

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussianset.h>

#include <QDebug>

namespace Avogadro::QtPlugins {

OrbitalTableModel::OrbitalTableModel(QWidget* parent)
  : QAbstractTableModel(parent)
{
  m_orbitals.clear();
}

OrbitalTableModel::~OrbitalTableModel() {}

int OrbitalTableModel::columnCount(const QModelIndex&) const
{
  return COUNT;
}

QVariant OrbitalTableModel::data(const QModelIndex& index, int role) const
{
  if ((role != Qt::DisplayRole && role != Qt::TextAlignmentRole) ||
      !index.isValid())
    return QVariant();

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  if (role == Qt::TextAlignmentRole) {
    switch (Column(index.column())) {
      case C_Energy:
        return toVariant(Qt::AlignRight |
                         Qt::AlignVCenter); // numeric alignment
      case C_Status:                        // everything else can be centered
      case C_Description:
      case C_Symmetry:
      default:
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    }
  }

  const Orbital* orb = m_orbitals.at(index.row());
  QString symbol; // use subscripts
  int subscriptStart;

  switch (Column(index.column())) {
    case C_Description:
      return orb->description;
    case C_Energy:
      return QString("%L1").arg(orb->energy, 0, 'f', 3);
    case C_Status: {
      // Check for divide by zero
      int percent;
      if (orb->max == orb->min)
        percent = 0;
      else {
        percent = 100 * (orb->current - orb->min) / float(orb->max - orb->min);
        // Adjust for stages
        int stages = (orb->totalStages == 0) ? 1 : orb->totalStages;
        percent /= float(stages);
        percent += (orb->stage - 1) * (100.0 / float(stages));
        // clamp to 100%
        if (percent > 100)
          percent = 100;
      }
      return QString("%L1%").arg(percent);
    }
    case C_Symmetry:
      symbol = orb->symmetry;
      if (symbol.length() > 1) {
        subscriptStart = 1;
        if (symbol[0] == '?')
          subscriptStart++;
        symbol.insert(subscriptStart, QString("<sub>"));
        symbol.append(QString("</sub>"));
      }
      symbol.replace('\'', QString("<sup>'</sup>"));
      symbol.replace('"', QString("<sup>\"</sup>"));
      return symbol;
    default:
    case COUNT:
      return QVariant();
  }
}

QVariant OrbitalTableModel::headerData(int section, Qt::Orientation orientation,
                                       int role) const
{
  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Horizontal) {
    switch (Column(section)) {
      case C_Description:
        return tr("Orbital");
      case C_Energy:
        return tr("Energy (eV)");
      case C_Symmetry:
        return tr("Symmetry");
      case C_Status:
        return tr("Status");
      default:
      case COUNT:
        return QVariant();
    }
  } else
    return QString::number(section + 1);
}

QModelIndex OrbitalTableModel::HOMO() const
{
  for (int i = 0; i < m_orbitals.size(); i++) {
    if (m_orbitals.at(i)->description == tr("HOMO", "Highest Occupied MO"))
      return index(i, 0);
  }
  return QModelIndex();
}

QModelIndex OrbitalTableModel::LUMO() const
{
  for (int i = 0; i < m_orbitals.size(); i++) {
    if (m_orbitals.at(i)->description == tr("LUMO", "Lowest Unoccupied MO"))
      return index(i, 0);
  }
  return QModelIndex();
}

// predicate for sorting below
bool orbitalIndexLessThan(const Orbital* o1, const Orbital* o2)
{
  return (o1->index < o2->index);
}

bool OrbitalTableModel::setOrbitals(const Core::BasisSet* basis)
{
  clearOrbitals();

  // assemble the orbital information
  // TODO: Alpha / Beta orbitals
  unsigned int homo = basis->homo();
  unsigned int lumo = basis->lumo();
  unsigned int count = homo - 1;
  bool leqHOMO = true; // orbital <= homo

  // energies and symmetries
  // TODO: handle both alpha and beta (separate columns?)
  // TODO: move moEnergies to the BasisSet class
  QList<QVariant> alphaEnergies;
  auto* gaussianBasis = dynamic_cast<const Core::GaussianSet*>(basis);
  if (gaussianBasis != nullptr) {
    auto moEnergies = gaussianBasis->moEnergy();
    alphaEnergies.reserve(moEnergies.size());
    for (double energy : moEnergies) {
      alphaEnergies.push_back(energy);
    }
  }

  // not sure if any import supports symmetry labels yet
  const auto labels = basis->symmetryLabels();
  QStringList alphaSymmetries;
  alphaSymmetries.reserve(labels.size());
  for (const std::string& label : labels) {
    alphaSymmetries.push_back(QString::fromStdString(label));
  }

  for (unsigned int i = 0; i < basis->molecularOrbitalCount(); i++) {
    QString num = "";
    if (i + 1 != homo && i + 1 != lumo) {
      num = (leqHOMO) ? "-" : "+";
      num += QString::number(count);
    }

    QString desc = QString("%1")
                     // (HOMO|LUMO)(+|-)[0-9]+
                     .arg((leqHOMO) ? tr("HOMO", "Highest Occupied MO") + num
                                    : tr("LUMO", "Lowest Unoccupied MO") + num);

    Orbital* orb = new Orbital;
    // Get the energy from the molecule property list, if available
    if (static_cast<unsigned int>(alphaEnergies.size()) > i)
      orb->energy = alphaEnergies[i].toDouble();
    else
      orb->energy = 0.0;
    // symmetries (if available)
    if (static_cast<unsigned int>(alphaSymmetries.size()) > i)
      orb->symmetry = alphaSymmetries[i];
    orb->index = i;
    orb->description = desc;
    orb->queueEntry = 0;
    orb->min = 0;
    orb->max = 0;
    orb->current = 0;

    m_orbitals.append(orb);
    if (i + 1 < homo)
      count--;
    else if (i + 1 == homo)
      leqHOMO = false;
    else if (i + 1 >= lumo)
      count++;
  }
  // sort the orbital list (not sure if this is necessary)
  std::sort(m_orbitals.begin(), m_orbitals.end(), orbitalIndexLessThan);

  // add the rows for all the new orbitals
  beginInsertRows(QModelIndex(), 0, m_orbitals.size() - 1);
  endInsertRows();
  return true;
}

bool OrbitalTableModel::clearOrbitals()
{
  if (m_orbitals.size() > 0) {
    beginRemoveRows(QModelIndex(), 0, m_orbitals.size() - 1);
    m_orbitals.clear();
    endRemoveRows();
  }

  return true;
}

void OrbitalTableModel::setOrbitalProgressRange(int orbital, int min, int max,
                                                int stage, int totalStages)
{
  Orbital* orb = m_orbitals[orbital];
  orb->min = min;
  orb->current = min;
  orb->max = max;
  orb->stage = stage;
  orb->totalStages = totalStages;
  // Update display
  QModelIndex status = index(orbital, int(C_Status), QModelIndex());
  emit dataChanged(status, status);
}

void OrbitalTableModel::incrementStage(int orbital, int newmin, int newmax)
{
  Orbital* orb = m_orbitals[orbital];
  orb->stage++;
  orb->min = newmin;
  orb->current = newmin;
  orb->max = newmax;
  // Update display
  QModelIndex status = index(orbital, C_Status, QModelIndex());
  emit dataChanged(status, status);
}

void OrbitalTableModel::setOrbitalProgressValue(int orbital, int currentValue)
{
  Orbital* orb = m_orbitals[orbital];
  orb->current = currentValue;
  // Update display
  QModelIndex status = index(orbital, C_Status, QModelIndex());
  emit dataChanged(status, status);
}

void OrbitalTableModel::finishProgress(int orbital)
{
  Orbital* orb = m_orbitals[orbital];
  orb->stage = 1;
  orb->totalStages = 1;
  orb->min = 0;
  orb->current = 1;
  orb->max = 1;

  // Update display
  QModelIndex status = index(orbital, C_Status, QModelIndex());
  emit dataChanged(status, status);
}

void OrbitalTableModel::resetProgress(int orbital)
{
  Orbital* orb = m_orbitals[orbital];
  orb->stage = 1;
  orb->totalStages = 1;
  orb->min = 0;
  orb->current = 0;
  orb->max = 0;

  // Update display
  QModelIndex status = index(orbital, C_Status, QModelIndex());
  emit dataChanged(status, status);
}

void OrbitalTableModel::setProgressToZero(int orbital)
{
  Orbital* orb = m_orbitals[orbital];
  orb->stage = 1;
  orb->totalStages = 1;
  orb->min = 0;
  orb->current = 0;
  orb->max = 1;

  // Update display
  QModelIndex status = index(orbital, C_Status, QModelIndex());
  emit dataChanged(status, status);
}

} // namespace Avogadro::QtPlugins

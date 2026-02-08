/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "orbitaltablemodel.h"
#include "orbitalwidget.h"

#include <avogadro/core/basisset.h>
#include <avogadro/core/gaussianset.h>

#include <QBrush>
#include <QColor>
#include <QDebug>
#include <QGuiApplication>
#include <QPalette>

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
  if (!index.isValid())
    return QVariant();

  const Orbital* orb = m_orbitals.at(index.row());

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  if (role == Qt::BackgroundRole) {
    // Tinted background for occupied orbitals
    if (orb->occupation >= 0.5f) {
      // Get default background and darken/lighten based on luminance
      QColor base = QGuiApplication::palette().color(QPalette::Base);
      // Use luminance to detect dark mode (dark mode has low luminance)
      int luminance =
        (base.red() * 299 + base.green() * 587 + base.blue() * 114) / 1000;
      if (luminance < 128) {
        // Dark mode: lighten the background
        return QBrush(base.lighter(200));
      } else {
        // Light mode: darken the background
        return QBrush(base.darker(120));
      }
    }
    return QVariant();
  }

  if (role == Qt::TextAlignmentRole) {
    switch (Column(index.column())) {
      case C_Energy:
        return toVariant(Qt::AlignRight |
                         Qt::AlignVCenter); // numeric alignment
      case C_Occupation:                    // everything else can be centered
      case C_Description:
      case C_Symmetry:
      default:
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    }
  }

  if (role != Qt::DisplayRole)
    return QVariant();
  QString symbol; // use subscripts
  int subscriptStart;

  switch (Column(index.column())) {
    case C_Description:
      return orb->description;
    case C_Energy:
      return QString("%L1").arg(orb->energy, 0, 'f', 3);
    case C_Occupation: {
      // Show occupation arrows based on electron type and occupation
      if (orb->occupation < 0.5f)
        return QString(); // unoccupied - show nothing

      switch (orb->electronType) {
        case Core::BasisSet::Paired:
          return QString::fromUtf8("⇅"); // paired electrons
        case Core::BasisSet::Alpha:
          return QString::fromUtf8("↑  "); // alpha (spin up)
        case Core::BasisSet::Beta:
          return QString::fromUtf8("  ↓"); // beta (spin down)
        default:
          return QString();
      }
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
    case C_ElectronType:
      // Return integer value for hidden column (used internally)
      return static_cast<int>(orb->electronType);
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
      case C_Occupation:
        return tr("Occupation");
      case C_ElectronType:
        return tr("Spin");
      default:
      case COUNT:
        return QVariant();
    }
  } else
    return QString::number(section + 1);
}

QModelIndex OrbitalTableModel::HOMO() const
{
  QString homoStr = tr("HOMO", "Highest Occupied MO");
  // First try to find alpha-HOMO (for open-shell) or plain HOMO (for closed)
  for (int i = 0; i < m_orbitals.size(); i++) {
    const QString& desc = m_orbitals.at(i)->description;
    if (desc == homoStr || desc == QString::fromUtf8("α-") + homoStr)
      return index(i, 0);
  }
  return QModelIndex();
}

QModelIndex OrbitalTableModel::LUMO() const
{
  QString lumoStr = tr("LUMO", "Lowest Unoccupied MO");
  // First try to find alpha-LUMO (for open-shell) or plain LUMO (for closed)
  for (int i = 0; i < m_orbitals.size(); i++) {
    const QString& desc = m_orbitals.at(i)->description;
    if (desc == lumoStr || desc == QString::fromUtf8("α-") + lumoStr)
      return index(i, 0);
  }
  return QModelIndex();
}

int OrbitalTableModel::orbitalIndex(int row) const
{
  if (row < 0 || row >= m_orbitals.size())
    return -1;
  return m_orbitals.at(row)->index;
}

Core::BasisSet::ElectronType OrbitalTableModel::electronType(int row) const
{
  if (row < 0 || row >= m_orbitals.size())
    return Core::BasisSet::Paired;
  return m_orbitals.at(row)->electronType;
}

// predicate for sorting by energy (for interleaving alpha/beta)
bool orbitalEnergyLessThan(const Orbital* o1, const Orbital* o2)
{
  return (o1->energy < o2->energy);
}

// Helper to create orbital description string
// e.g., "HOMO-1" or "alpha-HOMO"
// prefix is supplied for alpha/beta orbitals as UTF-8 characters
QString makeOrbitalDescription(unsigned int index, unsigned int homo,
                               unsigned int lumo, const QString& homoStr,
                               const QString& lumoStr, const QString& prefix)
{
  QString num = "";
  bool leqHOMO = (index + 1 <= homo);

  if (index + 1 != homo && index + 1 != lumo) {
    if (leqHOMO) {
      num = "-" + QString::number(homo - index - 1);
    } else {
      num = "+" + QString::number(index + 1 - lumo);
    }
  }

  QString desc = prefix;
  desc += (leqHOMO) ? homoStr + num : lumoStr + num;
  return desc;
}

bool OrbitalTableModel::setOrbitals(const Core::BasisSet* basis)
{
  clearOrbitals();

  auto* gaussianBasis = dynamic_cast<const Core::GaussianSet*>(basis);

  // Check if this is an open-shell calculation (UHF or ROHF)
  bool isOpenShell = false;
  if (gaussianBasis != nullptr) {
    Core::ScfType scfType = gaussianBasis->scfType();
    isOpenShell = (scfType == Core::Uhf || scfType == Core::Rohf);
  }

  // Also check if beta orbitals actually exist
  if (isOpenShell) {
    auto betaEnergies = basis->moEnergy(Core::BasisSet::Beta);
    if (betaEnergies.empty()) {
      isOpenShell = false; // No beta data, treat as closed-shell
    }
  }

  QString homoStr = tr("HOMO", "Highest Occupied MO");
  QString lumoStr = tr("LUMO", "Lowest Unoccupied MO");

  if (isOpenShell) {
    // Open-shell: create both alpha and beta orbitals
    unsigned int alphaHomo = basis->homo(Core::BasisSet::Alpha);
    unsigned int alphaLumo = basis->lumo(Core::BasisSet::Alpha);
    unsigned int betaHomo = basis->homo(Core::BasisSet::Beta);
    unsigned int betaLumo = basis->lumo(Core::BasisSet::Beta);

    auto alphaEnergies = basis->moEnergy(Core::BasisSet::Alpha);
    auto betaEnergies = basis->moEnergy(Core::BasisSet::Beta);
    auto alphaSymmetries = basis->symmetryLabels(Core::BasisSet::Alpha);
    auto betaSymmetries = basis->symmetryLabels(Core::BasisSet::Beta);
    auto alphaOccupancy = basis->moOccupancy(Core::BasisSet::Alpha);
    auto betaOccupancy = basis->moOccupancy(Core::BasisSet::Beta);

    unsigned int alphaCount =
      basis->molecularOrbitalCount(Core::BasisSet::Alpha);
    unsigned int betaCount = basis->molecularOrbitalCount(Core::BasisSet::Beta);

    // Create alpha orbitals
    for (unsigned int i = 0; i < alphaCount; i++) {
      Orbital* orb = new Orbital;
      orb->energy = (i < alphaEnergies.size()) ? alphaEnergies[i] : 0.0;
      orb->index = i;
      orb->electronType = Core::BasisSet::Alpha;
      orb->description = makeOrbitalDescription(
        i, alphaHomo, alphaLumo, homoStr, lumoStr, QString::fromUtf8("α-"));
      if (i < alphaSymmetries.size())
        orb->symmetry = QString::fromStdString(alphaSymmetries[i]);
      orb->queueEntry = nullptr;
      // Use occupancy data if available, otherwise fall back to HOMO-based
      if (i < alphaOccupancy.size())
        orb->occupation = static_cast<float>(alphaOccupancy[i]);
      else
        orb->occupation = (i + 1 <= alphaHomo) ? 1.0f : 0.0f;
      m_orbitals.append(orb);
    }

    // Create beta orbitals
    for (unsigned int i = 0; i < betaCount; i++) {
      Orbital* orb = new Orbital;
      orb->energy = (i < betaEnergies.size()) ? betaEnergies[i] : 0.0;
      orb->index = i;
      orb->electronType = Core::BasisSet::Beta;
      orb->description = makeOrbitalDescription(
        i, betaHomo, betaLumo, homoStr, lumoStr, QString::fromUtf8("β-"));
      if (i < betaSymmetries.size())
        orb->symmetry = QString::fromStdString(betaSymmetries[i]);
      orb->queueEntry = nullptr;
      // Use occupancy data if available, otherwise fall back to HOMO-based
      if (i < betaOccupancy.size())
        orb->occupation = static_cast<float>(betaOccupancy[i]);
      else
        orb->occupation = (i + 1 <= betaHomo) ? 1.0f : 0.0f;
      m_orbitals.append(orb);
    }

    // Sort by energy to interleave alpha and beta orbitals
    std::sort(m_orbitals.begin(), m_orbitals.end(), orbitalEnergyLessThan);

  } else {
    // Closed-shell (RHF): original behavior with paired orbitals
    unsigned int homo = basis->homo();
    unsigned int lumo = basis->lumo();

    auto moEnergies = basis->moEnergy(Core::BasisSet::Paired);
    auto symmetryLabels = basis->symmetryLabels(Core::BasisSet::Paired);
    auto moOccupancy = basis->moOccupancy(Core::BasisSet::Paired);

    for (unsigned int i = 0; i < basis->molecularOrbitalCount(); i++) {
      Orbital* orb = new Orbital;
      orb->energy = (i < moEnergies.size()) ? moEnergies[i] : 0.0;
      orb->index = i;
      orb->electronType = Core::BasisSet::Paired;
      orb->description =
        makeOrbitalDescription(i, homo, lumo, homoStr, lumoStr, QString());
      if (i < symmetryLabels.size())
        orb->symmetry = QString::fromStdString(symmetryLabels[i]);
      orb->queueEntry = nullptr;
      // Use occupancy data if available, otherwise fall back to HOMO-based
      if (i < moOccupancy.size())
        orb->occupation = static_cast<float>(moOccupancy[i]);
      else
        orb->occupation = (i + 1 <= homo) ? 2.0f : 0.0f;
      m_orbitals.append(orb);
    }
  }

  // add the rows for all the new orbitals
  if (!m_orbitals.isEmpty()) {
    beginInsertRows(QModelIndex(), 0, m_orbitals.size() - 1);
    endInsertRows();
  }
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

} // namespace Avogadro::QtPlugins

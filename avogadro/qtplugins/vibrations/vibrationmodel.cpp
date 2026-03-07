/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationmodel.h"

#include <avogadro/qtgui/molecule.h>

namespace Avogadro::QtPlugins {

VibrationModel::VibrationModel(QObject* p)
  : QAbstractItemModel(p), m_molecule(nullptr), m_hasRaman(false), m_hasSymmetry(false)
{
}

QModelIndex VibrationModel::parent(const QModelIndex&) const
{
  return QModelIndex();
}

int VibrationModel::rowCount(const QModelIndex& p) const
{
  if (p.isValid() || !m_molecule)
    return 0;
  else
    return m_molecule->vibrationFrequencies().size();
}

int VibrationModel::columnCount(const QModelIndex&) const
{
  // Base columns: Frequency, Intensity
  int count = 2;
  // Add Raman column if we have Raman data
  if (m_molecule && m_hasRaman)
    count++;
  // Add Symmetry column if we have symmetry labels
  if (m_molecule && m_hasSymmetry)
    count++;
  return count;
}

Qt::ItemFlags VibrationModel::flags(const QModelIndex&) const
{
  return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

void VibrationModel::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
  m_hasRaman = mol->vibrationRamanIntensities().size() > 0;
  m_hasSymmetry = mol->vibrationSymmetryLabels().size() > 0;
}

QVariant VibrationModel::headerData(int section, Qt::Orientation orientation,
                                    int role) const
{
  if (role == Qt::DisplayRole) {
    if (orientation == Qt::Horizontal) {
      int col = 0;
      if (section == col)
        return QString("Frequency (cm⁻¹)");
      col++;
      if (section == col)
        return QString("Intensity (km/mol)");
      col++;
      if (m_hasRaman) {
        if (section == col)
          return QString("Raman Intensity (a.u.)");
        col++;
      }
      if (m_hasSymmetry) {
        if (section == col)
          return QString("Symmetry");
      }
    } else if (orientation == Qt::Vertical) {
      return QString::number(section + 1);
    }
  }
  return QVariant();
}

bool VibrationModel::setData(const QModelIndex&, const QVariant&, int)
{
  return false;
}

QVariant VibrationModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || !m_molecule ||
      static_cast<int>(m_molecule->vibrationFrequencies().size()) <=
        idx.row()) {
    return QVariant();
  }

  if (role == Qt::DisplayRole) {
    int col = 0;
    // Frequency column
    if (idx.column() == col) {
      if (static_cast<int>(m_molecule->vibrationFrequencies().size()) >
          idx.row())
        return m_molecule->vibrationFrequencies()[idx.row()];
      else
        return "No value";
    }
    col++;
    
    // Intensity column
    if (idx.column() == col) {
      if (static_cast<int>(m_molecule->vibrationIRIntensities().size()) >
          idx.row())
        return m_molecule->vibrationIRIntensities()[idx.row()];
      else
        return "No value";
    }
    col++;
    
    // Raman column (if present)
    if (m_hasRaman) {
      if (idx.column() == col) {
        if (static_cast<int>(m_molecule->vibrationRamanIntensities().size()) >
            idx.row())
          return m_molecule->vibrationRamanIntensities()[idx.row()];
        else
          return "No value";
      }
      col++;
    }
    
    // Symmetry column (if present)
    if (m_hasSymmetry) {
      if (idx.column() == col) {
        auto labels = m_molecule->vibrationSymmetryLabels();
        if (static_cast<int>(labels.size()) > idx.row())
          return QString::fromStdString(labels[idx.row()]);
        else
          return QString();
      }
    }
    
    return "Invalid";
  }

  return QVariant();
}

QModelIndex VibrationModel::index(int row, int column,
                                  const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && m_molecule &&
        row < static_cast<int>(m_molecule->vibrationFrequencies().size()))
      return createIndex(row, column);
  return QModelIndex();
}

void VibrationModel::clear() {}
} // namespace Avogadro::QtPlugins

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "vibrationmodel.h"

#include <avogadro/qtgui/molecule.h>

namespace Avogadro::QtPlugins {

VibrationModel::VibrationModel(QObject* p)
  : QAbstractItemModel(p), m_molecule(nullptr), m_hasRaman(false)
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
  // do we have raman data?
  if (m_molecule && m_hasRaman)
    return 3;

  return 2;
}

Qt::ItemFlags VibrationModel::flags(const QModelIndex&) const
{
  return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
}

void VibrationModel::setMolecule(QtGui::Molecule* mol)
{
  m_molecule = mol;
  m_hasRaman = mol->vibrationRamanIntensities().size() > 0;
}

QVariant VibrationModel::headerData(int section, Qt::Orientation orientation,
                                    int role) const
{
  if (role == Qt::DisplayRole) {
    if (orientation == Qt::Horizontal) {
      switch (section) {
        case 0:
          return QString("Frequency (cm⁻¹)");
        case 1:
          return QString("Intensity (KM/mol)");
        case 2:
          return QString("Raman Intensity (Å⁴/amu)");
      }
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
  if (!idx.isValid() || idx.column() > 2 || !m_molecule ||
      m_molecule->vibrationFrequencies().size() <= idx.row()) {
    return QVariant();
  }

  if (role == Qt::DisplayRole) {
    switch (idx.column()) {
      case 0:
        if (m_molecule->vibrationFrequencies().size() > idx.row())
          return m_molecule->vibrationFrequencies()[idx.row()];
        else
          return "No value";
      case 1:
        if (m_molecule->vibrationIRIntensities().size() > idx.row())
          return m_molecule->vibrationIRIntensities()[idx.row()];
        else
          return "No value";
      case 2:
        if (m_molecule->vibrationRamanIntensities().size() > idx.row())
          return m_molecule->vibrationRamanIntensities()[idx.row()];
        else
          return "No value";
      default:
        return "Invalid";
    }
  }

  return QVariant();
}

QModelIndex VibrationModel::index(int row, int column,
                                  const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && m_molecule &&
        row < m_molecule->vibrationFrequencies().size())
      return createIndex(row, column);
  return QModelIndex();
}

void VibrationModel::clear()
{
}
}

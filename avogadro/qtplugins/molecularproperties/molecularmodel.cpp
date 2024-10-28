/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularmodel.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QRegularExpression>
#include <QtGui/QColor>

#include <limits>

namespace Avogadro {

using Avogadro::QtGui::Molecule;
using QtGui::Molecule;

MolecularModel::MolecularModel(QObject* parent)
  : QAbstractTableModel(parent), m_molecule(nullptr)
{
}

void MolecularModel::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
}

int MolecularModel::rowCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);

  if (!m_molecule)
    return 0;

  // we have 5 guaranteed rows (name, mass, formula atoms, bonds)
  // if we have residues, then two more (residues, chains)
  // if we have conformers, we should add another row
  // and then however many keys are in the property map
  int rows = 5;
  if (m_molecule->residueCount() > 0)
    rows += 1; // TODO chains
  if (m_molecule->coordinate3dCount() > 0)
    ++rows;

  const auto& properties = m_molecule->dataMap();
  rows += properties.names().size(); // 0 or more

  return rows;
}

int MolecularModel::columnCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);
  return 1; // values
}

QString formatFormula(Molecule* m)
{
  QString formula = QString::fromStdString(molecule->formula());
  QRegularExpression digitParser("(\\d+)");

  QRegularExpressionMatchIterator i = digitParser.globalMatch(formula);
  unsigned int offset = 0;
  while (i.hasNext()) {
    const QRegularExpressionMatch match = i.next();
    QString digits = match.captured(1);

    formula.replace(match.capturedStart(1) + offset, digits.size(),
                    QString("<sub>%1</sub>").arg(digits));
    offset += 11; // length of <sub>...</sub>
  }

  // add total charge as a superscript
  int charge = m->totalCharge();
  if (charge != 0)
    formula += QString("<sup>%1</sup>").arg(charge);

  return formula;
}

// Qt calls this for multiple "roles" across row / columns in the index
//   we also combine multiple types into this class, so lots of special cases
QVariant MolecularModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid() || m_molecule == nullptr)
    return QVariant();

  int row = index.row();
  int col = index.column();

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    return toVariant(Qt::AlignHCenter | Qt::AlignRight);
  }

  if (role != Qt::UserRole && role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  if (row == Name) {
    return QString::fromStdString(m_molecule->data("name").toString());
  } else if (row == Mass) {
    return m_molecule->mass();
  } else if (row == Formula) {
    return formatFormula(m_molecule);
  } else if (row == Atoms) {
    return QVariant::fromValue(m_molecule->atomCount());
  } else if (row == Bonds) {
    return QVariant::fromValue(m_molecule->bondCount());
  }

  int offset = row - Bonds;
  bool conformers = (m_molecule->coordinate3dCount() > 0);
  bool residues = (m_molecule->residueCount() > 0);
  if (conformers && offset == 0) {
    return m_molecule->coordinate3dCount(); // conformers first
  }
  offset -= conformers ? 1 : 0; // tweak for conformer line
  if (residues && offset == 0) {
    return QVariant::fromValue(m_molecule->residueCount()); // residues next
  }
  offset -= residues ? 1 : 0; // tweak for residues line
  /* TODO - chains
  if (residues && offset == 0) {
    return m_molecule->chainCount(); // chains next
  }
  */

  // now we're looping through the property map
  const auto map = m_molecule->dataMap();
  auto it = map.begin();
  std::advance(it, offset);
  if (it != map.end()) {
    return QString::fromStdString(it->second.toString());
  }

  return QVariant();
}

QVariant MolecularModel::headerData(int section, Qt::Orientation orientation,
                                    int role) const
{
  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    if (orientation == Qt::Vertical) {
      return Qt::AlignHCenter; // XYZ coordinates
    }
  }

  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Horizontal) {
    if (section == 0)
      return tr("Property");
    else if (section == 1)
      return tr("Value");
  } else if (orientation == Qt::Vertical) {
    if (section == Name)
      return tr("Molecule Name");
    else if (section == Mass)
      return tr("Molecular Mass (g/mol)");
    else if (section == Formula)
      return tr("Chemical Formula");
    else if (section == Atoms)
      return tr("Number of Atoms");
    else if (section == Bonds)
      return tr("Number of Bonds");

    int offset = section - Bonds;
    bool conformers = (m_molecule->coordinate3dCount() > 0);
    bool residues = (m_molecule->residueCount() > 0);
    if (conformers && offset == 0) {
      return tr("Coordinate Sets"); // conformers first
    }
    offset -= conformers ? 1 : 0; // tweak for conformer line
    if (residues && offset == 0) {
      return tr("Number of Residues");
    }
    offset -= residues ? 1 : 0; // tweak for residues line
    /* TODO - chains
    if (residues && offset == 0) {
      return tr("Number of Chains");
    }
    */

    // now we're looping through the property map
    const auto map = m_molecule->dataMap();
    auto it = map.begin();
    std::advance(it, offset);
    if (it != map.end()) {
      return QString::fromStdString(it->first);
    }

    return QVariant();

  } else // row headers
    return QVariant();

  return QVariant();
}

Qt::ItemFlags MolecularModel::flags(const QModelIndex& index) const
{
  if (!index.isValid())
    return Qt::ItemIsEnabled;

  // return QAbstractItemModel::flags(index) | Qt::ItemIsEditable
  // for the types and columns that can be edited
  auto editable = Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable;

  return QAbstractItemModel::flags(index);
}

bool MolecularModel::setData(const QModelIndex& index, const QVariant& value,
                             int role)
{
  if (!index.isValid())
    return false;

  if (role != Qt::EditRole)
    return false;

  // TODO allow editing name
  return false;
}

void MolecularModel::updateTable(unsigned int flags)
{
  if (flags & Molecule::Added || flags & Molecule::Removed) {
    // tear it down and rebuild the model
    beginResetModel();
    endResetModel();
  } else {
    // we can just update the current data
    emit dataChanged(
      QAbstractItemModel::createIndex(0, 0),
      QAbstractItemModel::createIndex(rowCount(), columnCount()));
  }
}

} // end namespace Avogadro

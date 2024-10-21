/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularmodel.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtGui/QColor>

#include <limits>

namespace Avogadro {

using Avogadro::QtGui::Molecule;
using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using std::numeric_limits;
using std::pair;
using std::vector;

MolecularModel::MolecularModel(QObject* parent)
  : QAbstractTableModel(parent), m_molecule(nullptr)
{
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
    rows += 2;
  if (m_molecule->coordinate3dCount() > 0)
    ++rows;

  const auto& properties = m_molecule->dataMap();
  if (m_molecule->propertyKeys().size() > 0)
    rows += m_molecule->propertyKeys().size();

  return 0;
}

int MolecularModel::columnCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);
  return 1; // values
}

QString formatFormula(std::string f)
{
  QString formula = QString::fromStdString(f);
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
    return toVariant(Qt::AlignHCenter | Qt::AlignVRight);
  }

  if (role != Qt::UserRole && role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  if (row == Name) {
    return QString::fromStdString(m_molecule->data("name").toString());
  } else if (row == Mass) {
    return m_molecule->mass();
  } else if (row == Formula) {
    return formatFormula(m_molecule->formula());
  } else if (row == Atoms) {
    return m_molecule->atomCount();
  } else if (row == Bonds) {
    return m_molecule->bondCount();
  }

  // TODO: figure out if we have conformers, etc.

  /*
  } else if (row == Residues) {
    return m_molecule->residueCount();
  } else if (row == Chains) {
    return m_molecule->chainCount();
  } else if (row == Conformers) {
    return m_molecule->coordinate3dCount();
  }
  */

  // now we're looping through the property map
  const auto map = m_molecule->dataMap();
  unsigned int howManyRows = row - 5; // tweak for residues, etc.

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
      return tr("Name");
    else if (section == Mass)
      return tr("Molar Mass (g/mol)");
    else if (section == Formula)
      return tr("Formula");
    else if (section == Atoms)
      return tr("Number of Atoms");
    else if (section == Bonds)
      return tr("Number of Bonds");

    else
      return QVariant();

  } else // row headers
    return QVariant();
}

return QVariant();
}

Qt::ItemFlags MolecularModel::flags(const QModelIndex& index) const
{
  if (!index.isValid())
    return Qt::ItemIsEnabled;

  // return QAbstractItemModel::flags(index) | Qt::ItemIsEditable
  // for the types and columns that can be edited
  auto editable = Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable;
  if (m_type == AtomType) {
    if (index.column() == AtomDataElement ||
        index.column() == AtomDataFormalCharge || index.column() == AtomDataX ||
        index.column() == AtomDataY || index.column() == AtomDataZ)
      return editable;
    // TODO: Color
  } else if (m_type == BondType) {
    if (index.column() == BondDataOrder || index.column() == BondDataLength)
      return editable;
  } else if (m_type == ResidueType) {
    // TODO: Color
  } else if (m_type == AngleType) {
    if (index.column() == AngleDataValue)
      return editable;
  } else if (m_type == TorsionType) {
    if (index.column() == TorsionDataValue)
      return editable;
  }

  return QAbstractItemModel::flags(index);
}

bool MolecularModel::setData(const QModelIndex& index, const QVariant& value,
                             int role)
{
  if (!index.isValid())
    return false;

  if (role != Qt::EditRole)
    return false;

  // If an item is actually editable, we should invalidate the cache
  // We can still use the cached data -- we just invalidate now
  // So that we can call "return" and have the cache invalid when we leave
  m_validCache = false;
  auto* undoMolecule = m_molecule->undoMolecule();

  if (m_type == AtomType) {
    Vector3 v = m_molecule->atomPosition3d(index.row());

    switch (static_cast<AtomColumn>(index.column())) {
      case AtomDataFormalCharge: {
        bool ok;
        int charge = value.toInt(&ok);
        if (ok) {
          undoMolecule->setFormalCharge(index.row(), charge);
        }
        break;
      }
      case AtomDataElement: { // atomic number
        // Try first as a number
        bool ok;
        int atomicNumber = value.toInt(&ok);
        if (ok)
          undoMolecule->setAtomicNumber(index.row(), atomicNumber);
        else {
          // try a symbol
          atomicNumber = Core::Elements::atomicNumberFromSymbol(
            value.toString().toStdString());

          if (atomicNumber != Avogadro::InvalidElement) {
            undoMolecule->setAtomicNumber(index.row(), atomicNumber);
          } else
            return false;
        } // not a number
        break;
      }
      case AtomDataX:
        v[0] = value.toDouble();
        break;
      case AtomDataY:
        v[1] = value.toDouble();
        break;
      case AtomDataZ:
        v[2] = value.toDouble();
        break;
      default:
        return false;
    }
    undoMolecule->setAtomPosition3d(index.row(), v);

    // cleanup atom changes
    emit dataChanged(index, index);
    m_molecule->emitChanged(Molecule::Atoms);
    return true;
  } else if (m_type == BondType) {
    switch (static_cast<BondColumn>(index.column())) {
      case BondDataOrder:
        undoMolecule->setBondOrder(index.row(), value.toInt());
        break;
      case BondDataLength:
        setBondLength(index.row(), value.toDouble());
        break;
      default:
        return false;
    }

    emit dataChanged(index, index);
    m_molecule->emitChanged(Molecule::Bonds);
    return true;
  } else if (m_type == AngleType) {
    if (index.column() == AngleDataValue) {
      setAngle(index.row(), value.toDouble());
      emit dataChanged(index, index);
      m_molecule->emitChanged(Molecule::Atoms);
      return true;
    }
  } else if (m_type == TorsionType) {
    if (index.column() == TorsionDataValue) {
      setTorsion(index.row(), value.toDouble());
      emit dataChanged(index, index);
      m_molecule->emitChanged(Molecule::Atoms);
      return true;
    }
  }

  return false;
}

void MolecularModel::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule && molecule != m_molecule) {
    m_molecule = molecule;

    updateCache();

    connect(m_molecule, SIGNAL(changed(unsigned int)), this,
            SLOT(updateTable(unsigned int)));
  }
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

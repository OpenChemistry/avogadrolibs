/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymodel.h"

#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/dihedraliterator.h>

#include <QBrush>
#include <QColor>
#include <QDebug>

#include <limits>

namespace Avogadro {

using Avogadro::QtGui::Molecule;
using std::numeric_limits;
using std::pair;
using std::vector;

using SecondaryStructure = Avogadro::Core::Residue::SecondaryStructure;

const int AtomColumns = 6;    // element, valence, x, y, z, color
const int BondColumns = 5;    // type, atom 1, atom 2, bond order, length
const int AngleColumns = 5;   // type, atom 1, atom 2, atom 3, angle
const int TorsionColumns = 6; // type, atom 1, atom 2, atom 3, atom 4, dihedral
const int ResidueColumns =
  6; // name, number, chain, secondary structure, heterogen, color
const int ConformerColumns = 2; // number, energy

inline double distance(Vector3 v1, Vector3 v2)
{
  Vector3 v3 = v1 - v2;
  return v3.norm();
}

inline QString angleTypeString(unsigned char a, unsigned char b,
                               unsigned char c)
{
  return QString("%1%2%3")
    .arg(Core::Elements::symbol(a))
    .arg(Core::Elements::symbol(b))
    .arg(Core::Elements::symbol(c));
}

inline QString torsionTypeString(unsigned char a, unsigned char b,
                                 unsigned char c, unsigned char d)
{
  return QString("%1%2%3%4")
    .arg(Core::Elements::symbol(a))
    .arg(Core::Elements::symbol(b))
    .arg(Core::Elements::symbol(c))
    .arg(Core::Elements::symbol(d));
}

PropertyModel::PropertyModel(PropertyType type, QObject* parent)
  : QAbstractTableModel(parent), m_type(type), m_molecule(nullptr)
{}

int PropertyModel::rowCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);

  if (!m_validCache)
    updateCache();

  if (m_type == AtomType) {
    return m_molecule->atomCount();
  } else if (m_type == BondType) {
    return m_molecule->bondCount();
  } else if (m_type == ResidueType) {
    return m_molecule->residueCount();
  } else if (m_type == AngleType) {
    return m_angles.size();
  } else if (m_type == TorsionType) {
    return m_torsions.size();
  } else if (m_type == ConformerType) {
    return m_molecule->coordinate3dCount();
  }

  return 0;
}

int PropertyModel::columnCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);
  switch (m_type) {
    case AtomType:
      return AtomColumns; // element, valence, X, Y, Z, color
    case BondType:
      return BondColumns; // type, atom 1, atom 2, order, length
    case AngleType:
      return AngleColumns; // type, atom 1, atom 2, atom 3, angle
    case TorsionType:
      return TorsionColumns; // type, atom 1, atom 2, atom 3, atom 4, dihedral
    case ResidueType:
      return ResidueColumns; // name, number, chain, secondary structure,
                             // heterogen, color
    case ConformerType:
      return ConformerColumns; // number, energy
  }
  return 0;
}

// Qt calls this for multiple "roles" across row / columns in the index
//   we also combine multiple types into this class, so lots of special cases
QVariant PropertyModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid())
    return QVariant();

  int row = index.row();
  int col = index.column();

  // qDebug() << " data: " << row << " " << col << " " << role;

  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    if (m_type == ConformerType) {
      return Qt::AlignRight + Qt::AlignVCenter; // energies
    } else if (m_type == AtomType) {
      if ((index.column() == AtomDataCharge) ||
          (index.column() == AtomDataColor))
        return Qt::AlignRight + Qt::AlignVCenter;
      else
        return Qt::AlignHCenter + Qt::AlignVCenter;
    } else if (m_type == BondType) {
      if (index.column() == BondDataLength)
        return Qt::AlignRight + Qt::AlignVCenter; // bond length
      else
        return Qt::AlignHCenter + Qt::AlignVCenter;
    } else if (m_type == AngleType) {
      if (index.column() == AngleDataValue)
        return Qt::AlignRight + Qt::AlignVCenter; // angle
      else
        return Qt::AlignHCenter + Qt::AlignVCenter;
    } else if (m_type == TorsionType) {
      if (index.column() == TorsionDataValue)
        return Qt::AlignRight + Qt::AlignVCenter; // dihedral angle
      else
        return Qt::AlignHCenter + Qt::AlignVCenter;
    } else if (m_type == ResidueType) {
      return Qt::AlignHCenter + Qt::AlignVCenter;
    }
  }

  if (role == Qt::DecorationRole) {
    // color for atom and residue
    if (m_type == AtomType && col == AtomDataColor &&
        row < m_molecule->atomCount()) {

      auto c = m_molecule->color(row);
      QColor color(c[0], c[1], c[2]);
      return color;
    } else if (m_type == ResidueType && col == ResidueDataColor &&
               row < m_molecule->residueCount()) {

      auto c = m_molecule->residue(row).color();
      QColor color(c[0], c[1], c[2]);
      return color;
    }
  }

  bool sortRole =
    (role == Qt::UserRole); // from the proxy model to handle floating-point

  if (role != Qt::UserRole && role != Qt::DisplayRole)
    return QVariant();

  //  if (!m_validCache)
  //    updateCache();

  if (m_type == AtomType) {
    AtomColumn column = static_cast<AtomColumn>(index.column());

    if (row >= m_molecule->atomCount() || column > AtomColumns)
      return QVariant(); // invalid index

    QString format("%L1");

    // Return Data
    switch (column) {
      case AtomDataElement:
        return Core::Elements::symbol(m_molecule->atomicNumber(row));
      case AtomDataValence:
        return QVariant::fromValue(m_molecule->bonds(row).size());
      case AtomDataX:
        return QString("%L1").arg(m_molecule->atomPosition3d(row).x(), 0, 'f',
                                  4);
      case AtomDataY:
        return QString("%L1").arg(m_molecule->atomPosition3d(row).y(), 0, 'f',
                                  4);
      case AtomDataZ:
        return QString("%L1").arg(m_molecule->atomPosition3d(row).z(), 0, 'f',
                                  4);
      case AtomDataColor:
      default:
        return QVariant(); // nothing to show
    }

  } else if (m_type == BondType) {

    BondColumn column = static_cast<BondColumn>(index.column());

    if (row >= m_molecule->bondCount() || column > BondColumns)
      return QVariant(); // invalid index

    auto bond = m_molecule->bond(row);
    auto atom1 = bond.atom1();
    auto atom2 = bond.atom2();
    switch (column) {
      case BondDataType:
        return QString("%1-%2")
          .arg(Core::Elements::symbol(atom1.atomicNumber()))
          .arg(Core::Elements::symbol(atom2.atomicNumber()));
      case BondDataAtom1:
        return QVariant::fromValue(atom1.index() + 1);
      case BondDataAtom2:
        return QVariant::fromValue(atom2.index() + 1);
      case BondDataOrder:
        return bond.order();
      default: // length, rounded to 4 decimals
        return QString("%L1").arg(
          distance(atom1.position3d(), atom2.position3d()), 0, 'f', 3);
    }
  } else if (m_type == ResidueType) {

    ResidueColumn column = static_cast<ResidueColumn>(index.column());

    if (row >= m_molecule->residueCount() || column > ResidueColumns)
      return QVariant(); // invalid index

    auto residue = m_molecule->residue(row);
    // name, number, chain, secondary structure
    // color is handled above
    switch (column) {
      case ResidueDataName:
        return residue.residueName().c_str();
      case ResidueDataID:
        return QVariant::fromValue(residue.residueId());
      case ResidueDataChain:
        return QString(residue.chainId());
      case ResidueDataSecStructure:
        return secStructure(residue.secondaryStructure());
      case ResidueDataHeterogen:
        return QString(residue.isHeterogen() ? "X" : "");
      default:
        return QVariant();
    }
  } else if (m_type == AngleType) {

    AngleColumn column = static_cast<AngleColumn>(index.column());
    if (row > m_angles.size() || column > AngleColumns)
      return QVariant(); // invalid index

    auto angle = m_angles[row];
    auto atomNumber1 = m_molecule->atomicNumber(std::get<0>(angle));
    auto atomNumber2 = m_molecule->atomicNumber(std::get<1>(angle));
    auto atomNumber3 = m_molecule->atomicNumber(std::get<2>(angle));

    Vector3 a1 = m_molecule->atomPosition3d(std::get<0>(angle));
    Vector3 a2 = m_molecule->atomPosition3d(std::get<1>(angle));
    Vector3 a3 = m_molecule->atomPosition3d(std::get<2>(angle));

    switch (column) {
      case AngleDataType:
        return angleTypeString(atomNumber1, atomNumber2, atomNumber3);
      case AngleDataAtom1:
        return QVariant::fromValue(std::get<0>(angle) + 1);
      case AngleDataAtom2:
        return QVariant::fromValue(std::get<1>(angle) + 1);
      case AngleDataAtom3:
        return QVariant::fromValue(std::get<2>(angle) + 1);
      case AngleDataValue:
        return QString("%L1").arg(calcAngle(a1, a2, a3), 0, 'f', 3);
      default:
        return QVariant();
    }

  } else if (m_type == TorsionType) {

    TorsionColumn column = static_cast<TorsionColumn>(index.column());
    if (row > m_torsions.size() || column > TorsionColumns)
      return QVariant(); // invalid index

    auto torsion = m_torsions[row];
    auto atomNumber1 = m_molecule->atomicNumber(std::get<0>(torsion));
    auto atomNumber2 = m_molecule->atomicNumber(std::get<1>(torsion));
    auto atomNumber3 = m_molecule->atomicNumber(std::get<2>(torsion));
    auto atomNumber4 = m_molecule->atomicNumber(std::get<3>(torsion));

    Vector3 a1 = m_molecule->atomPosition3d(std::get<0>(torsion));
    Vector3 a2 = m_molecule->atomPosition3d(std::get<1>(torsion));
    Vector3 a3 = m_molecule->atomPosition3d(std::get<2>(torsion));
    Vector3 a4 = m_molecule->atomPosition3d(std::get<3>(torsion));

    switch (column) {
      case TorsionDataType:
        return torsionTypeString(atomNumber1, atomNumber2, atomNumber3,
                                 atomNumber4);

      case TorsionDataAtom1:
        return QVariant::fromValue(std::get<0>(torsion) + 1);
      case TorsionDataAtom2:
        return QVariant::fromValue(std::get<1>(torsion) + 1);
      case TorsionDataAtom3:
        return QVariant::fromValue(std::get<2>(torsion) + 1);
      case TorsionDataAtom4:
        return QVariant::fromValue(std::get<3>(torsion) + 1);
      case TorsionDataValue:
        return QString("%L1").arg(calcDihedral(a1, a2, a3, a4), 0, 'f', 3);
      default:
        return QVariant();
    }
  }

  return QVariant();
}

QVariant PropertyModel::headerData(int section, Qt::Orientation orientation,
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

  if (m_type == AtomType) {
    if (orientation == Qt::Horizontal) {

      unsigned int column = static_cast<AtomColumn>(section);
      switch (column) {
        case AtomDataElement:
          return tr("Element");
        case AtomDataValence:
          return tr("Valence");
        case AtomDataX:
          return tr("X (Å)");
        case AtomDataY:
          return tr("Y (Å)");
        case AtomDataZ:
          return tr("Z Å)");
        case AtomDataColor:
          return tr("Color");
      }
    } else
      return tr("Atom") + QString(" %1").arg(section + 1);

  } else if (m_type == BondType) {
    if (orientation == Qt::Horizontal) {
      unsigned int column = static_cast<BondColumn>(section);
      switch (column) {
        case BondDataType:
          return tr("Type");
        case BondDataAtom1:
          return tr("Start Atom");
        case BondDataAtom2:
          return tr("End Atom");
        case BondDataOrder:
          return tr("Bond Order");
        default: // A bond length
          return tr("Length (Å)", "in Angstrom");
      }
    } else
      // Bond ordering starts at 0
      return tr("Bond") + QString(" %1").arg(section + 1);
  } else if (m_type == ResidueType) {

    if (orientation == Qt::Horizontal) {
      unsigned int column = static_cast<ResidueColumn>(section);
      switch (column) {
        case ResidueDataName:
          return tr("Name");
        case ResidueDataID:
          return tr("ID");
        case ResidueDataChain:
          return tr("Chain");
        case ResidueDataSecStructure:
          return tr("Secondary Structure");
        case ResidueDataHeterogen:
          return tr("Heterogen");
        case ResidueDataColor:
          return tr("Color");
      }
    } else // row headers
      return QString("%L1").arg(section + 1);
  } else if (m_type == AngleType) {

    if (orientation == Qt::Horizontal) {
      unsigned int column = static_cast<AngleColumn>(section);
      switch (column) {
        case AngleDataType:
          return tr("Type");
        case AngleDataAtom1:
          return tr("Atom 1");
        case AngleDataAtom2:
          return tr("Vertex");
        case AngleDataAtom3:
          return tr("Atom 3");
        case AngleDataValue:
          return tr("Angle (°)");
      }
    } else // row headers
      return QString("%L1").arg(section + 1);
  } else if (m_type == TorsionType) {
    if (orientation == Qt::Horizontal) {
      unsigned int column = static_cast<TorsionColumn>(section);
      switch (column) {
        case TorsionDataType:
          return tr("Type");
        case TorsionDataAtom1:
          return tr("Atom 1");
        case TorsionDataAtom2:
          return tr("Atom 2");
        case TorsionDataAtom3:
          return tr("Atom 3");
        case TorsionDataAtom4:
          return tr("Atom 4");
        case TorsionDataValue:
          return tr("Angle (°)");
      }
    } else // row headers
      return QString("%L1").arg(section + 1);
  }

  return QVariant();
}

Qt::ItemFlags PropertyModel::flags(const QModelIndex& index) const
{
  if (!index.isValid())
    return Qt::ItemIsEnabled;

  return QAbstractItemModel::flags(index) | Qt::ItemIsEditable |
         Qt::ItemIsSelectable;
}

bool PropertyModel::setData(const QModelIndex& index, const QVariant& value,
                            int role)
{
  if (!index.isValid())
    return false;

  if (role != Qt::EditRole)
    return false;

  return false;
}

void PropertyModel::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
  updateCache();

  connect(m_molecule, SIGNAL(changed(unsigned int)), this,
          SLOT(updateTable(unsigned int)));
}

QString PropertyModel::secStructure(unsigned int type) const
{
  switch (type) {
    case SecondaryStructure::piHelix:
      return tr("π Helix", "pi helix");
    case SecondaryStructure::bend:
      return tr("Bend", "protein bend secondary structure");
    case SecondaryStructure::alphaHelix:
      return tr("α Helix", "alpha helix");
    case SecondaryStructure::betaSheet:
      return tr("β Sheet", "beta sheet");
    case SecondaryStructure::helix310:
      return tr("3-10 helix", "3-10 helix");
    case SecondaryStructure::betaBridge:
      return tr("β Bridge", "beta bridge");
    case SecondaryStructure::turn:
      return tr("Turn", "protein turn secondary structure");
    case SecondaryStructure::coil:
      return tr("Coil", "protein coil secondary structure");
    default:
      return QString(); // implied unknown
  }
}

void PropertyModel::updateTable(unsigned int flags)
{
  if (flags & Molecule::Added || flags & Molecule::Removed) {
    // tear it down and rebuild the model
    updateCache();
    beginResetModel();
    endResetModel();
  } else {
    // we can just update the current data
    emit dataChanged(
      QAbstractItemModel::createIndex(0, 0),
      QAbstractItemModel::createIndex(rowCount(), columnCount()));
  }
}

void PropertyModel::updateCache() const
{
  m_validCache = true;
  m_angles.clear();
  m_torsions.clear();

  if (m_molecule == nullptr)
    return;

  if (m_type == AngleType) {
    Core::AngleIterator aIter(m_molecule);
    auto angle = aIter.begin();
    while (angle != aIter.end()) {
      m_angles.push_back(angle);
      angle = ++aIter;
    }
  } else if (m_type == TorsionType) {
    Core::DihedralIterator dIter(m_molecule);
    auto torsion = dIter.begin();
    while (torsion != dIter.end()) {
      m_torsions.push_back(torsion);
      torsion = ++dIter;
    }
  }
}

Core::Angle PropertyModel::getAngle(unsigned int angle) const
{
  if (angle >= m_angles.size())
    return Core::Angle();

  return m_angles[angle];
}

Core::Dihedral PropertyModel::getTorsion(unsigned int torsion) const
{
  if (torsion >= m_torsions.size())
    return Core::Dihedral();

  return m_torsions[torsion];
}

} // end namespace Avogadro

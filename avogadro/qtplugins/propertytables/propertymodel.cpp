/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "propertymodel.h"

#include <avogadro/calc/chargemanager.h>
#include <avogadro/core/array.h>
#include <avogadro/core/atom.h>
#include <avogadro/core/bond.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/angletools.h>
#include <avogadro/core/dihedraliterator.h>

#include <QtCore/QDebug>
#include <QtGui/QColor>

#include <limits>

#include <Eigen/Geometry>

namespace Avogadro {

using Avogadro::Core::Array;
using Avogadro::QtGui::Molecule;
using QtGui::Molecule;
using QtGui::RWAtom;
using QtGui::RWBond;
using std::numeric_limits;
using std::pair;
using std::vector;

using SecondaryStructure = Avogadro::Core::Residue::SecondaryStructure;

// element, valence, formal charge, partial charge, x, y, z, label, color
const int AtomColumns = 9;
// type, atom 1, atom 2, bond order, length, label
const int BondColumns = 6;
// type, atom 1, atom 2, atom 3, angle
const int AngleColumns = 5;
// type, atom 1, atom 2, atom 3, atom 4, dihedral
const int TorsionColumns = 6;
// name, number, chain, secondary structure, heterogen, color
const int ResidueColumns = 6;
// number, rmsd, energy or more depending on available properties
const int ConformerColumns = 1;

// compute the RMSD between the two sets of coordinates
inline double calculateRMSD(const Array<Vector3>& v1, const Array<Vector3>& v2)
{
  // if they're not the same length, it's an error
  if (v1.size() != v2.size())
    return numeric_limits<double>::quiet_NaN();

  double sum = 0.0;
  for (size_t i = 0; i < v1.size(); ++i) {
    Vector3 diff = v1[i] - v2[i];
    sum += diff.squaredNorm();
  }
  return sqrt(sum / v1.size());
}

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
{
}

int PropertyModel::rowCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);

  if (!m_validCache)
    updateCache();

  switch (m_type) {
    case AtomType:
      return m_molecule->atomCount();
    case BondType:
      return m_molecule->bondCount();
    case ResidueType:
      return m_molecule->residueCount();
    case AngleType:
      return m_angles.size();
    case TorsionType:
      return m_torsions.size();
    case ConformerType:
      return m_molecule->coordinate3dCount();
    default:
      return 0;
  }

  return 0;
}

int PropertyModel::columnCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);
  switch (m_type) {
    case AtomType:
      return AtomColumns; // see above
    case BondType:
      return BondColumns; // see above
    case AngleType:
      return AngleColumns; // see above
    case TorsionType:
      return TorsionColumns;
    case ResidueType:
      return ResidueColumns;
    case ConformerType: {
      if (m_molecule->hasData("energies"))
        return ConformerColumns + 1;
      else
        return ConformerColumns;
    }
    default:
      return 0;
  }
  return 0;
}

QString partialChargeType(Molecule* molecule)
{
  QString type;

  std::set<std::string> types = molecule->partialChargeTypes();
  if (types.size() > 0) {
    type = QString(types.cbegin()->c_str());
  } else {
    // find something
    const auto options =
      Calc::ChargeManager::instance().identifiersForMolecule(*molecule);
    if (options.size() > 0) {
      // look for GFN2 or AM1BCC, then MMFF94 then Gasteiger
      if (options.find("GFN2") != options.end())
        type = "GFN2";
      else if (options.find("am1bcc") != options.end())
        type = "am1bcc";
      else if (options.find("mmff94") != options.end())
        type = "mmff94";
      else if (options.find("gasteiger") != options.end())
        type = "gasteiger";
      else
        type = *options.begin()->c_str();
    }
  }

  return type;
}

QString formatChargeType(QString type)
{
  if (type == "gfn2")
    return "GFN2";
  else if (type == "am1bcc")
    return "AM1BCC";
  else if (type == "mmff94")
    return "MMFF94";
  else if (type == "gasteiger")
    return "Gasteiger";
  else if (type.startsWith("eem"))
    return "EEM";
  else if (type == "qeq")
    return "QEq";
  else if (type.toLower() == "mulliken")
    return "Mulliken";
  else if (type.toLower() == "lowdin")
    return "Lowdin";
  else if (type.toLower() == "chelpg")
    return "CHELPG";
  else if (type.toLower() == "hirshfeld")
    return "Hirshfeld";
  else
    return type;
}

QString partialCharge(Molecule* molecule, int atom)
{
  // TODO: we need to track type and/or calling the charge calculator
  float charge = 0.0;
  std::string type = partialChargeType(molecule).toStdString();

  MatrixX charges =
    Calc::ChargeManager::instance().partialCharges(type, *molecule);
  charge = charges(atom, 0);

  return QString("%L1").arg(charge, 0, 'f', 3);
}

// Qt calls this for multiple "roles" across row / columns in the index
//   we also combine multiple types into this class, so lots of special cases
QVariant PropertyModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid())
    return QVariant();

  int row = index.row();
  int col = index.column();

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    if (m_type == ConformerType) {
      return toVariant(Qt::AlignRight | Qt::AlignVCenter); // energies
    } else if (m_type == AtomType) {
      if ((index.column() == AtomDataCharge) ||
          (index.column() == AtomDataColor))
        return toVariant(Qt::AlignRight | Qt::AlignVCenter);
      else
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    } else if (m_type == BondType) {
      if (index.column() == BondDataLength)
        return toVariant(Qt::AlignRight | Qt::AlignVCenter); // bond length
      else
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    } else if (m_type == AngleType) {
      if (index.column() == AngleDataValue)
        return toVariant(Qt::AlignRight | Qt::AlignVCenter); // angle
      else
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    } else if (m_type == TorsionType) {
      if (index.column() == TorsionDataValue)
        return toVariant(Qt::AlignRight | Qt::AlignVCenter); // dihedral angle
      else
        return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    } else if (m_type == ResidueType) {
      return toVariant(Qt::AlignHCenter | Qt::AlignVCenter);
    } else if (m_type == ConformerType) {
      return toVariant(Qt::AlignRight |
                       Qt::AlignVCenter); // RMSD or other properties
    }
  }

  if (role == Qt::DecorationRole) {
    // color for atom and residue
    if (m_type == AtomType && col == AtomDataColor &&
        row < static_cast<int>(m_molecule->atomCount())) {

      auto c = m_molecule->color(row);
      QColor color(c[0], c[1], c[2]);
      return color;
    } else if (m_type == ResidueType && col == ResidueDataColor &&
               row < static_cast<int>(m_molecule->residueCount())) {

      auto c = m_molecule->residue(row).color();
      QColor color(c[0], c[1], c[2]);
      return color;
    }
  }

  if (role != Qt::UserRole && role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  if (m_type == AtomType) {
    auto column = static_cast<AtomColumn>(index.column());

    if (row >= static_cast<int>(m_molecule->atomCount()) ||
        column > AtomColumns) {
      return QVariant(); // invalid index
    }

    QString format("%L1");

    // Return Data
    switch (column) {
      case AtomDataElement:
        return Core::Elements::symbol(m_molecule->atomicNumber(row));
      case AtomDataValence:
        return QVariant::fromValue(m_molecule->bonds(row).size());
      case AtomDataFormalCharge:
        return m_molecule->formalCharge(row);
      case AtomDataPartialCharge:
        return partialCharge(m_molecule, row);
      case AtomDataX:
        if (role == Qt::UserRole)
          // Return the x coordinate as a double for sorting
          return m_molecule->atomPosition3d(row).x();
        else // format fixed to 4 decimals
        {
          auto formatted =
            QString("%L1").arg(m_molecule->atomPosition3d(row).x(), 0, 'f', 4);
          if (m_molecule->frozenAtom(row) || m_molecule->frozenAtomAxis(row, 0))
            formatted += "🔒";
          return formatted;
        }

      case AtomDataY:
        if (role == Qt::UserRole)
          // Return the y coordinate as a double for sorting
          return m_molecule->atomPosition3d(row).y();
        else // format fixed to 4 decimals
        {
          auto formatted =
            QString("%L1").arg(m_molecule->atomPosition3d(row).y(), 0, 'f', 4);
          if (m_molecule->frozenAtom(row) || m_molecule->frozenAtomAxis(row, 1))
            formatted += "🔒";
          return formatted;
        }
      case AtomDataZ:
        if (role == Qt::UserRole)
          // Return the z coordinate as a double for sorting
          return m_molecule->atomPosition3d(row).z();
        else // format fixed to 4 decimals
        {
          auto formatted =
            QString("%L1").arg(m_molecule->atomPosition3d(row).z(), 0, 'f', 4);
          if (m_molecule->frozenAtom(row) || m_molecule->frozenAtomAxis(row, 2))
            formatted += "🔒";
          return formatted;
        }
      case AtomDataLabel:
        return m_molecule->atomLabel(row).c_str();
      case AtomDataColor:
      default:
        return QVariant(); // nothing to show
    }

  } else if (m_type == BondType) {

    auto column = static_cast<BondColumn>(index.column());

    if (row >= static_cast<int>(m_molecule->bondCount()) ||
        column > BondColumns) {
      return QVariant(); // invalid index
    }

    auto bond = m_molecule->bond(row);
    auto atom1 = bond.atom1();
    auto atom2 = bond.atom2();
    bool isConstrained = false;

    // check constraints for this bond
    for (auto& constraint : m_molecule->constraints()) {
      if (constraint.aIndex() == atom1.index() &&
          constraint.bIndex() == atom2.index()) {
        isConstrained = true;
        break;
      }
    }

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
      case BondDataLabel:
        return m_molecule->bondLabel(row).c_str();
      default: // length, rounded to 4 decimals
        if (role == Qt::UserRole)
          // Return the bond length as a double for sorting
          return distance(atom1.position3d(), atom2.position3d());
        else {
          QString formatted = QString("%L1").arg(
            distance(atom1.position3d(), atom2.position3d()), 0, 'f', 3);
          if (isConstrained)
            formatted += "🔒";
          return formatted;
        }
    }
  } else if (m_type == ResidueType) {

    auto column = static_cast<ResidueColumn>(index.column());

    if (row >= static_cast<int>(m_molecule->residueCount()) ||
        column > ResidueColumns) {
      return QVariant(); // invalid index
    }

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

    auto column = static_cast<AngleColumn>(index.column());
    if (row > static_cast<int>(m_angles.size()) || column > AngleColumns)
      return QVariant(); // invalid index

    auto angle = m_angles[row];
    auto atomNumber1 = m_molecule->atomicNumber(std::get<0>(angle));
    auto atomNumber2 = m_molecule->atomicNumber(std::get<1>(angle));
    auto atomNumber3 = m_molecule->atomicNumber(std::get<2>(angle));

    Vector3 a1 = m_molecule->atomPosition3d(std::get<0>(angle));
    Vector3 a2 = m_molecule->atomPosition3d(std::get<1>(angle));
    Vector3 a3 = m_molecule->atomPosition3d(std::get<2>(angle));

    bool isConstrained = false;

    // check constraints for this angle
    for (auto& constraint : m_molecule->constraints()) {
      if (constraint.aIndex() == std::get<0>(angle) &&
          constraint.bIndex() == std::get<1>(angle) &&
          constraint.cIndex() == std::get<2>(angle)) {
        isConstrained = true;
        break;
      }
    }

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
        if (role == Qt::UserRole)
          // Return the angle as a double for sorting
          return calculateAngle(a1, a2, a3);
        else { // format fixed to 3 decimals
          QString formatted =
            QString("%L1").arg(calculateAngle(a1, a2, a3), 0, 'f', 3);
          if (isConstrained)
            formatted += "🔒";
          return formatted;
        }
      default:
        return QVariant();
    }

  } else if (m_type == TorsionType) {

    auto column = static_cast<TorsionColumn>(index.column());
    if (row > static_cast<int>(m_torsions.size()) || column > TorsionColumns)
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

    bool isConstrained = false;

    // check constraints for this torsion
    for (auto& constraint : m_molecule->constraints()) {
      if (constraint.aIndex() == std::get<0>(torsion) &&
          constraint.bIndex() == std::get<1>(torsion) &&
          constraint.cIndex() == std::get<2>(torsion) &&
          constraint.dIndex() == std::get<3>(torsion)) {
        isConstrained = true;
        break;
      }
    }

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
        if (role == Qt::UserRole)
          // Return the dihedral angle as a double for sorting
          return calculateDihedral(a1, a2, a3, a4);
        else { // format fixed to 3 decimals
          QString format =
            QString("%L1").arg(calculateDihedral(a1, a2, a3, a4), 0, 'f', 3);
          if (isConstrained)
            format += "🔒";
          return format;
        }
      default:
        return QVariant();
    }
  } else if (m_type == ConformerType) {
    auto column = static_cast<ConformerColumn>(index.column());
    if (row >= static_cast<int>(m_molecule->coordinate3dCount()) ||
        column > ConformerColumns) {
      return QVariant(); // invalid index
    }

    switch (column) {
      case ConformerDataRMSD: { // rmsd
        double rmsd = 0.0;
        if (row > 0) {
          rmsd = calculateRMSD(m_molecule->coordinate3d(row),
                               m_molecule->coordinate3d(0));
        }
        if (role == Qt::UserRole)
          // Return the RMSD as a double for sorting
          return rmsd;
        else // format fixed to 3 decimals
          return QString("%L1 Å").arg(rmsd, 0, 'f', 3);
      }
      case ConformerDataEnergy: {
        double energy = 0.0;
        if (m_molecule->hasData("energies")) {
          std::vector<double> energies = m_molecule->data("energies").toList();
          // calculate the minimum
          double minEnergy = std::numeric_limits<double>::max();
          for (double e : energies) {
            minEnergy = std::min(minEnergy, e);
          }
          if (row < static_cast<int>(energies.size()))
            energy = energies[row] - minEnergy;
        }
        if (role == Qt::UserRole)
          // Return the energy as a double for sorting
          return energy;
        else // format fixed to 4 decimals
          return QString("%L1").arg(energy, 0, 'f', 4);
      }
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
        case AtomDataFormalCharge:
          return tr("Formal Charge");
        case AtomDataPartialCharge: {
          QString charge =
            tr("%1 Partial Charge", "e.g. MMFF94 Partial Charge or "
                                    "Gasteiger Partial Charge");
          return charge.arg(formatChargeType(partialChargeType(m_molecule)));
        }
        case AtomDataX:
          return tr("X (Å)");
        case AtomDataY:
          return tr("Y (Å)");
        case AtomDataZ:
          return tr("Z (Å)");
        case AtomDataLabel:
          return tr("Label");
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
        case BondDataLabel:
          return tr("Label");
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
  } else if (m_type == ConformerType) {
    // check if we have energies
    bool hasEnergies = (m_molecule->hasData("energies"));
    if (orientation == Qt::Horizontal) {
      unsigned int column = static_cast<ConformerColumn>(section);
      switch (column) {
        case ConformerDataRMSD:
          return tr("RMSD (Å)", "root mean squared displacement in Angstrom");
        case ConformerDataEnergy:
          // should only hit this if we have energies anyway
          return hasEnergies ? tr("Energy (kcal/mol)") : tr("Property");
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

  // return QAbstractItemModel::flags(index) | Qt::ItemIsEditable
  // for the types and columns that can be edited
  auto editable = Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable;
  if (m_type == AtomType) {
    if (index.column() == AtomDataElement ||
        index.column() == AtomDataFormalCharge || index.column() == AtomDataX ||
        index.column() == AtomDataY || index.column() == AtomDataZ ||
        index.column() == AtomDataLabel)
      return editable;
    // TODO: Color
  } else if (m_type == BondType) {
    if (index.column() == BondDataOrder || index.column() == BondDataLength ||
        index.column() == BondDataLabel)
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

bool PropertyModel::setData(const QModelIndex& index, const QVariant& value,
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
      case AtomDataLabel:
        undoMolecule->setAtomLabel(index.row(), value.toString().toStdString());
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
      case BondDataLabel:
        undoMolecule->setBondLabel(index.row(), value.toString().toStdString());
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

void PropertyModel::buildFragment(const QtGui::RWBond& bond,
                                  const QtGui::RWAtom& startAtom)
{
  m_fragment.clear();
  if (!fragmentRecurse(bond, startAtom, startAtom)) {
    // If this returns false, then a cycle has been found. Only move startAtom
    // in this case.
    m_fragment.clear();
  }
  m_fragment.push_back(m_molecule->undoMolecule()->atomUniqueId(startAtom));
}

bool PropertyModel::fragmentRecurse(const QtGui::RWBond& bond,
                                    const QtGui::RWAtom& startAtom,
                                    const QtGui::RWAtom& currentAtom)
{
  // does our cycle include both bonded atoms?
  const RWAtom bondedAtom(bond.getOtherAtom(startAtom));
  auto* undoMolecule = m_molecule->undoMolecule();

  Core::Array<RWBond> bonds = undoMolecule->bonds(currentAtom);

  for (auto& it : bonds) {
    if (it != bond) { // Skip the current bond
      const RWAtom nextAtom = it.getOtherAtom(currentAtom);
      if (nextAtom != startAtom && nextAtom != bondedAtom) {
        // Skip atoms that have already been added. This prevents infinite
        // recursion on cycles in the fragments
        int uid = undoMolecule->atomUniqueId(nextAtom);
        if (!fragmentHasAtom(uid)) {
          m_fragment.push_back(uid);
          if (!fragmentRecurse(it, startAtom, nextAtom))
            return false;
        }
      } else if (nextAtom == bondedAtom) {
        // If we've found the bonded atom, the bond is in a cycle
        return false;
      }
    } // *it != bond
  }   // foreach bond
  return true;
}

inline bool PropertyModel::fragmentHasAtom(int uid) const
{
  return std::find(m_fragment.begin(), m_fragment.end(), uid) !=
         m_fragment.end();
}

void PropertyModel::transformFragment() const
{
  auto* undoMolecule = m_molecule->undoMolecule();
  undoMolecule->beginMergeMode(tr("Adjust Fragment"));
  for (int it : m_fragment) {
    RWAtom atom = m_molecule->undoMolecule()->atomByUniqueId(it);
    if (atom.isValid()) {
      Vector3 pos = atom.position3d();
      pos = m_transform * pos;
      atom.setPosition3d(pos);
    }
  }
  undoMolecule->endMergeMode();
}

void PropertyModel::setBondLength(unsigned int index, double length)
{
  if (m_molecule == nullptr)
    return;

  if (index >= m_molecule->bondCount())
    return;

  // figure out how much to move and the vector of displacement
  auto bond = m_molecule->undoMolecule()->bond(index);
  Vector3 v1 = bond.atom1().position3d();
  Vector3 v2 = bond.atom2().position3d();
  Vector3 diff = v2 - v1;
  double currentLength = diff.norm();
  diff.normalize();
  Vector3 delta = diff * (length - currentLength);

  buildFragment(bond, bond.atom2());

  m_transform.setIdentity();
  m_transform.translate(delta);

  transformFragment();

  m_molecule->emitChanged(QtGui::Molecule::Modified | QtGui::Molecule::Atoms);
}

void PropertyModel::setAngle(unsigned int index, double newValue)
{
  // the index refers to the angle

  auto angle = m_angles[index];
  auto atom1 = m_molecule->undoMolecule()->atom(std::get<0>(angle));
  auto atom2 = m_molecule->undoMolecule()->atom(std::get<1>(angle));
  auto atom3 = m_molecule->undoMolecule()->atom(std::get<2>(angle));

  auto bond = m_molecule->undoMolecule()->bond(atom1, atom2);
  Vector3 a = atom1.position3d();
  Vector3 b = atom2.position3d();
  Vector3 c = atom3.position3d();
  const double currentValue = calculateAngle(a, b, c);
  Vector3 ab = b - a;
  Vector3 bc = c - b;

  // Axis of rotation is the cross product of the vectors
  const Vector3 axis((ab.cross(bc)).normalized());
  // Angle of rotation
  const double change = (newValue - currentValue) * M_PI / 180.0;

  // Build transform
  m_transform.setIdentity();
  m_transform.translate(b);
  m_transform.rotate(Eigen::AngleAxis(-change, axis));
  m_transform.translate(-b);

  // Build the fragment if needed:
  if (m_fragment.empty())
    buildFragment(bond, atom2);

  // Perform transformation
  transformFragment();
}

void PropertyModel::setTorsion(unsigned int index, double newValue)
{

  auto torsion = m_torsions[index];
  auto atom1 = m_molecule->undoMolecule()->atom(std::get<0>(torsion));
  auto atom2 = m_molecule->undoMolecule()->atom(std::get<1>(torsion));
  auto atom3 = m_molecule->undoMolecule()->atom(std::get<2>(torsion));
  auto atom4 = m_molecule->undoMolecule()->atom(std::get<3>(torsion));

  auto bond = m_molecule->undoMolecule()->bond(atom2, atom3);
  Vector3 a = atom1.position3d();
  Vector3 b = atom2.position3d();
  Vector3 c = atom3.position3d();
  Vector3 d = atom4.position3d();
  const double currentValue = calculateDihedral(a, b, c, d);

  // Axis of rotation
  const Vector3 axis((c - b).normalized());
  // Angle of rotation
  const double change = (newValue - currentValue) * M_PI / 180.0;

  // Build transform
  m_transform.setIdentity();
  m_transform.translate(c);
  m_transform.rotate(Eigen::AngleAxis(change, axis));
  m_transform.translate(-c);

  // Build the fragment if needed:
  if (m_fragment.empty())
    buildFragment(bond, atom3);

  // Perform transformation
  transformFragment();
}

void PropertyModel::setMolecule(QtGui::Molecule* molecule)
{
  if (molecule && molecule != m_molecule) {
    m_molecule = molecule;

    updateCache();

    connect(m_molecule, SIGNAL(changed(unsigned int)), this,
            SLOT(updateTable(unsigned int)));
  }
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

Real PropertyModel::getAngleValue(unsigned int angle) const
{
  if (angle >= m_angles.size())
    return 0.0;

  auto a = m_angles[angle];
  auto atom1 = m_molecule->undoMolecule()->atom(std::get<0>(a));
  auto atom2 = m_molecule->undoMolecule()->atom(std::get<1>(a));
  auto atom3 = m_molecule->undoMolecule()->atom(std::get<2>(a));
  Vector3 a1 = atom1.position3d();
  Vector3 a2 = atom2.position3d();
  Vector3 a3 = atom3.position3d();
  return calculateAngle(a1, a2, a3);
}

Core::Dihedral PropertyModel::getTorsion(unsigned int torsion) const
{
  if (torsion >= m_torsions.size())
    return Core::Dihedral();

  return m_torsions[torsion];
}

Real PropertyModel::getTorsionValue(unsigned int torsion) const
{
  if (torsion >= m_torsions.size())
    return 0.0;

  auto t = m_torsions[torsion];
  auto atom1 = m_molecule->undoMolecule()->atom(std::get<0>(t));
  auto atom2 = m_molecule->undoMolecule()->atom(std::get<1>(t));
  auto atom3 = m_molecule->undoMolecule()->atom(std::get<2>(t));
  auto atom4 = m_molecule->undoMolecule()->atom(std::get<3>(t));
  Vector3 a1 = atom1.position3d();
  Vector3 a2 = atom2.position3d();
  Vector3 a3 = atom3.position3d();
  Vector3 a4 = atom4.position3d();
  return calculateDihedral(a1, a2, a3, a4);
}

} // end namespace Avogadro

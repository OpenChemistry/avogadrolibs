/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef PROPMODEL_H
#define PROPMODEL_H

#include <QtCore/QAbstractTableModel>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QString>

#include <avogadro/core/angleiterator.h>
#include <avogadro/core/dihedraliterator.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <Eigen/Geometry>

namespace Avogadro {

namespace Core {
class PropertyMap;
}

namespace QtGui {
class Molecule;
}

enum PropertyType
{
  Other = 0,
  AtomType,
  BondType,
  AngleType,
  TorsionType,
  ConformerType,
  ResidueType,
  MoleculeType,
};

class PropertyModel : public QAbstractTableModel
{
  Q_OBJECT

public slots:
  void updateTable(unsigned int flags);

public:
  explicit PropertyModel(PropertyType type, QObject* parent = nullptr);

  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index, int role) const override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole) override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const override;

  void setMolecule(QtGui::Molecule* molecule);

  // Return what type of model this is
  PropertyType type() const { return m_type; };
  bool isColorIndex(const QModelIndex& index) const;

  // Value type for a new user-created custom property column.
  enum class CustomPropertyType
  {
    Double,
    Int,
    String
  };

  // Returns true if this model holds per-entity properties that the user can
  // extend with custom columns (atom, bond, residue, conformer tables).
  bool supportsCustomProperties() const;

  // Create a new (empty) custom property column with the given @p name and
  // value @p type, then refresh the table. Returns false if the name is empty,
  // already in use, or the model does not support custom properties.
  bool addCustomProperty(const QString& name, CustomPropertyType type);

  // Partial charge type selection
  QStringList availableChargeTypes() const;
  void setChargeType(const QString& type);
  QString chargeType() const { return m_chargeType; }

  // Generate all data pertaining to angles and torsions
  void updateCache() const;

  // Get the angle for a given index
  Core::Angle getAngle(unsigned int angle) const;
  Real getAngleValue(unsigned int angle) const;

  // Get the torson for a given index
  Core::Dihedral getTorsion(unsigned int torsion) const;
  Real getTorsionValue(unsigned int torsion) const;

private:
  PropertyType m_type;
  QtGui::Molecule* m_molecule;
  QString m_chargeType; // user-selected charge type override (empty = auto)

  // Custom (per-entity) property columns from Molecule::*Properties()
  struct CustomColumn
  {
    enum Type
    {
      Double,
      Int,
      String,
      Matrix
    };
    std::string name;
    Type type;
  };

  mutable bool m_validCache;
  mutable std::vector<Core::Angle> m_angles;
  mutable std::vector<Core::Dihedral> m_torsions;
  mutable std::vector<CustomColumn> m_customColumns;

  // The per-entity property map backing this table (atom, bond, residue, or
  // conformer), or nullptr for computed tables (angle, torsion).
  Core::PropertyMap* propertyMap();
  const Core::PropertyMap* propertyMap() const;
  // Number of rows (entities) in this table for the current molecule.
  Index entityCount() const;
  int baseColumnCount() const;

  // Track structure counts to detect actual structural changes vs
  // coordinate-only
  mutable Index m_lastAtomCount = 0;
  mutable Index m_lastBondCount = 0;

  QString secStructure(unsigned int type) const;

  std::vector<int> m_fragment;
  Eigen::Affine3d m_transform;
  bool fragmentHasAtom(int uid) const;
  void buildFragment(const QtGui::RWBond& bond, const QtGui::RWAtom& startAtom);
  bool fragmentRecurse(const QtGui::RWBond& bond,
                       const QtGui::RWAtom& startAtom,
                       const QtGui::RWAtom& currentAtom);

  void setBondLength(unsigned int index, double value);
  void setAngle(unsigned int index, double newValue);
  void setTorsion(unsigned int index, double newValue);
  void transformFragment() const;

  QtGui::RWAtom otherBondedAtom(const QtGui::RWBond& bond,
                                const QtGui::RWAtom& atom) const
  {
    return bond.atom1() == atom ? bond.atom2() : bond.atom1();
  }

  /*
   * For each category (atom, bond etc), an enum specifies which columns hold
   * which data.
   */

  // Atom Data
  enum AtomColumn
  {
    AtomDataElement = 0,
    AtomDataValence,
    AtomDataFormalCharge,
    AtomDataPartialCharge,
    AtomDataX,
    AtomDataY,
    AtomDataZ,
    AtomDataLabel,
    AtomDataIsotope,
    AtomDataColor,
  };

  // Bond Data
  enum BondColumn
  {
    BondDataType = 0,
    BondDataAtom1,
    BondDataAtom2,
    BondDataOrder,
    BondDataLength,
    BondDataLabel
  };

  // Angle Data
  enum AngleColumn
  {
    AngleDataType = 0,
    AngleDataAtom1,
    AngleDataAtom2,
    AngleDataAtom3,
    AngleDataValue
  };

  // Torsion Data
  enum TorsionColumn
  {
    TorsionDataType = 0,
    TorsionDataAtom1,
    TorsionDataAtom2,
    TorsionDataAtom3,
    TorsionDataAtom4,
    TorsionDataValue
  };

  // Conformer Data
  enum ConformerColumn
  {
    ConformerDataRMSD = 0,
    ConformerDataEnergy
  };

  // Residue Data
  enum ResidueColumn
  {
    ResidueDataName = 0,
    ResidueDataID,
    ResidueDataChain,
    ResidueDataSecStructure,
    ResidueDataLabel,
    ResidueDataColor,
    ResidueDataHeterogen
  };
};

} // end namespace Avogadro

#endif

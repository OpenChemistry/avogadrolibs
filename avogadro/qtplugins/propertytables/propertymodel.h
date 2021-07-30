/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef PROPMODEL_H
#define PROPMODEL_H

#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QAbstractTableModel>
namespace Avogadro {

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
  void moleculeChanged();

public:
  explicit PropertyModel(PropertyType type, QObject* parent = 0);

  int rowCount(const QModelIndex& parent = QModelIndex()) const;
  int columnCount(const QModelIndex& parent = QModelIndex()) const;
  QVariant data(const QModelIndex& index, int role) const;
  Qt::ItemFlags flags(const QModelIndex& index) const;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole);
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const;

  void setMolecule(QtGui::Molecule* molecule);

  // Return what type of model this is
  PropertyType type() const { return m_type; };

  // Generate all data pertaining to atoms, bonds, angles etc
  void updateCache() const;

  // Empty all items in the cache
  //void clearCache() const;

  // Return the number of conformers we are displaying
  // unsigned int numConformers() const;

  // Given a model index, return the conformer it refers to
  // unsigned int conformerFromIndex(const QModelIndex &index) const;

private:
  PropertyType m_type;
  mutable int m_rowCount;
  QtGui::Molecule* m_molecule;

  /*
   * For each category (atom, bond etc), an enum specifies which columns hold
   * which data.
   */

  // Atom Data
  enum AtomColumn
  {
    AtomDataElement = 0,
    AtomDataValence,
    AtomDataX,
    AtomDataY,
    AtomDataZ,
    AtomDataColor,
    AtomDataCharge,
    AtomDataCustom,
  };

  // Bond Data
  enum BondColumn
  {
    BondDataType = 0,
    BondDataAtom1,
    BondDataAtom2,
    BondDataOrder,
    BondDataLength
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
    ConformerDataType = 0,
    ConformerDataEnergy
  };

  // Residue Data
  enum ResidueColumn
  {
    ResidueDataName = 0,
    ResidueDataID,
    ResidueDataChain,
    ResidueDataSecStructure,
    ResidueDataHeterogen,
    ResidueDataColor
  };

};

} // end namespace Avogadro

#endif

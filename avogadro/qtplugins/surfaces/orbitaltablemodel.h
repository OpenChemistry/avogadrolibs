/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ORBITALTABLEMODEL_H
#define AVOGADRO_QTPLUGINS_ORBITALTABLEMODEL_H

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>

#include <avogadro/core/basisset.h>

namespace Avogadro::Core {
class BasisSet;
}

namespace Avogadro::QtPlugins {

struct calcInfo;

struct Orbital
{
  double energy;
  int index;
  Core::BasisSet::ElectronType electronType; // Paired, Alpha, or Beta
  QString description;                       // (HOMO|LUMO)[(+|-)N]
  QString symmetry;                          // e.g., A1g (with subscripts)
  calcInfo* queueEntry;
  float occupation; // 0, 1, or 2 (supports future fractional)
};

// Used for sorting:
class OrbitalSortingProxyModel : public QSortFilterProxyModel
{
  Q_OBJECT

public:
  OrbitalSortingProxyModel(QObject* parent = nullptr)
    : QSortFilterProxyModel(parent), m_HOMOFirst(false){};

  bool isHOMOFirst() { return m_HOMOFirst; };
  void HOMOFirst(bool b) { m_HOMOFirst = b; };

protected:
  // Compare orbital values
  bool lessThan(const QModelIndex& left,
                const QModelIndex& right) const override
  {
    if (m_HOMOFirst)
      return left.row() < right.row();
    else
      return left.row() > right.row();
  }

private:
  bool m_HOMOFirst;
};

class OrbitalTableModel : public QAbstractTableModel
{
  Q_OBJECT

public:
  enum Column
  {
    C_Description = 0,
    C_Energy,
    C_Symmetry,
    C_Occupation,   // Shows arrows: ⇅ for paired, ↑ for alpha, ↓ for beta
    C_ElectronType, // hidden column for alpha/beta tracking

    COUNT
  };

  //! Constructor
  explicit OrbitalTableModel(QWidget* parent = nullptr);
  //! Deconstructor
  ~OrbitalTableModel() override;

  int rowCount(const QModelIndex&) const override { return m_orbitals.size(); };
  int columnCount(const QModelIndex&) const override;

  QVariant data(const QModelIndex& index,
                int role = Qt::DisplayRole) const override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role) const override;

  QModelIndex HOMO() const;
  QModelIndex LUMO() const;

  //! Get the orbital index (into basis set) for a given row
  int orbitalIndex(int row) const;
  //! Get the electron type for a given row
  Core::BasisSet::ElectronType electronType(int row) const;

  bool setOrbitals(const Core::BasisSet* basis);
  bool clearOrbitals();

private:
  QList<Orbital*> m_orbitals;
};
} // namespace Avogadro::QtPlugins

#endif

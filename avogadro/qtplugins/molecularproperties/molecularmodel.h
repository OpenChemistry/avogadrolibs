/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef MOLECULARMODEL_H
#define MOLECULARMODEL_H

#include <QtCore/QAbstractTableModel>
#include <QtCore/QList>
#include <QtCore/QObject>
#include <QtCore/QString>

class QNetworkAccessManager;
class QNetworkReply;

#include <avogadro/core/variantmap.h>
#include <avogadro/qtgui/rwmolecule.h>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

enum FixedRowType
{
  Name = 0,
  Mass,
  Formula,
  Atoms,
  Bonds
  // these are the fixed rows
};

class MolecularModel : public QAbstractTableModel
{
  Q_OBJECT

public slots:
  void updateTable(unsigned int flags);
  void updateNameReady(QNetworkReply* reply); // reply from network
  void canUpdateName();                       // don't do it too often

public:
  explicit MolecularModel(QObject* parent = 0);

  int rowCount(const QModelIndex& parent = QModelIndex()) const override;
  int columnCount(const QModelIndex& parent = QModelIndex()) const override;
  QVariant data(const QModelIndex& index, int role) const override;
  Qt::ItemFlags flags(const QModelIndex& index) const override;
  bool setData(const QModelIndex& index, const QVariant& value,
               int role = Qt::EditRole) override;
  QVariant headerData(int section, Qt::Orientation orientation,
                      int role = Qt::DisplayRole) const override;

  void setMolecule(QtGui::Molecule* molecule);

  QString name() const;

private:
  QtGui::Molecule* m_molecule = nullptr;
  mutable QString m_name;
  mutable bool m_nameRequestPending = false;

  bool m_autoName = true;
  bool m_nameUpdateNeeded = true;
  Core::VariantMap m_propertiesCache;

  QNetworkAccessManager* m_network = nullptr;
};

} // end namespace Avogadro

#endif

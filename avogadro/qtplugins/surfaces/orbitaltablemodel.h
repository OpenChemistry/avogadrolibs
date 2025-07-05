/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_ORBITALTABLEMODEL_H
#define AVOGADRO_QTPLUGINS_ORBITALTABLEMODEL_H

#include <QAbstractTableModel>
#include <QApplication>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>

namespace Avogadro::Core {
class BasisSet;
}

namespace Avogadro::QtPlugins {

struct calcInfo;

struct Orbital
{
  double energy;
  int index;
  QString description; // (HOMO|LUMO)[(+|-)N]
  QString symmetry;    // e.g., A1g (with subscripts)
  calcInfo* queueEntry;
  // Progress data:
  int min;
  int max;
  int current;
  int stage;
  int totalStages;
};

// Allow progress bars to be embedded in the table
class ProgressBarDelegate : public QStyledItemDelegate
{
  Q_OBJECT
public:
  ProgressBarDelegate(QObject* parent = 0) : QStyledItemDelegate(parent) {};
  QSize sizeHint(const QStyleOptionViewItem&, const QModelIndex&) const override
  {
    return QSize(60, 30);
  };

  void paint(QPainter* p, const QStyleOptionViewItem& o,
             const QModelIndex& ind) const override
  {
    QStyleOptionProgressBar opt;
    // Call initFrom() which will set the style based on the parent
    // GRH: This is critical to get things right on Mac
    //   otherwise the status bars always look disabled
    opt.initFrom(qobject_cast<QWidget*>(this->parent()));

    opt.rect = o.rect;
    opt.minimum = 1; // percentage
    opt.maximum = 100;
    opt.textVisible = true;
    int percent = ind.model()->data(ind, Qt::DisplayRole).toInt();
    opt.progress = percent;
    opt.text = QString("%1%").arg(QString::number(percent));
    QApplication::style()->drawControl(QStyle::CE_ProgressBar, &opt, p);
  }
};

// Used for sorting:
class OrbitalSortingProxyModel : public QSortFilterProxyModel
{
  Q_OBJECT

public:
  OrbitalSortingProxyModel(QObject* parent = 0)
    : QSortFilterProxyModel(parent), m_HOMOFirst(false) {};

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
    C_Status, // also occupation (0/1/2)

    COUNT
  };

  //! Constructor
  explicit OrbitalTableModel(QWidget* parent = 0);
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

  bool setOrbitals(const Core::BasisSet* basis);
  bool clearOrbitals();

  // Stages are used for multi-step processes, e.g. cube, posmesh, negmesh, etc
  void setOrbitalProgressRange(int orbital, int min, int max, int stage,
                               int totalStages);
  void incrementStage(int orbital, int newmin, int newmax);
  void setOrbitalProgressValue(int orbital, int currentValue);
  void finishProgress(int orbital);
  void resetProgress(int orbital);
  void setProgressToZero(int orbital);

private:
  QList<Orbital*> m_orbitals;
};
} // namespace Avogadro::QtPlugins

#endif

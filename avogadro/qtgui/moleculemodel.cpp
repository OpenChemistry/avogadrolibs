/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "moleculemodel.h"
#include "molecule.h"

#include <QtCore/QFileInfo>
#include <QtGui/QColor>
#include <QtGui/QIcon>
#include <QtGui/QPalette>

namespace Avogadro::QtGui {

MoleculeModel::MoleculeModel(QObject* p)
  : QAbstractItemModel(p), m_activeMolecule(nullptr)
{
  const QPalette defaultPalette;
  bool darkMode = (defaultPalette.color(QPalette::WindowText).lightness() >
                   defaultPalette.color(QPalette::Window).lightness());
  loadIcons(darkMode);
}

QModelIndex MoleculeModel::parent(const QModelIndex&) const
{
  return QModelIndex();
}

void MoleculeModel::loadIcons(bool darkMode)
{
  QString iconPath = ":icons/fallback/32x32/";
  QString plusIconPath =
    iconPath + (darkMode ? "plus-dark.png" : "plus-light.png");
  QString closeIconPath =
    iconPath + (darkMode ? "cross-dark.png" : "cross-light.png");

  m_plusIcon = QIcon(plusIconPath);
  m_closeIcon = QIcon(closeIconPath);
}

int MoleculeModel::rowCount(const QModelIndex& p) const
{
  if (p.isValid())
    return 0;
  else
    return m_molecules.size() + 1;
}

int MoleculeModel::columnCount(const QModelIndex&) const
{
  return 2;
}

Qt::ItemFlags MoleculeModel::flags(const QModelIndex& idx) const
{

  if (idx.row() == m_molecules.size())
    return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
  if (idx.column() == 0)
    return static_cast<Qt::ItemFlags>(Qt::ItemIsEditable | Qt::ItemIsEnabled);
  return Qt::ItemIsEnabled;
}

bool MoleculeModel::setData(const QModelIndex& idx, const QVariant& value,
                            int role)
{
  if (!idx.isValid() || idx.column() > 2)
    return false;

  auto* object = static_cast<QObject*>(idx.internalPointer());
  auto* mol = qobject_cast<Molecule*>(object);
  if (!mol)
    return false;

  switch (role) {
    case Qt::CheckStateRole:
      m_activeMolecule = mol;
      if (value == Qt::Checked /*&& !item->isEnabled()*/) {
        // item->setEnabled(true);
        emit moleculeStateChanged(mol);
      } else if (value == Qt::Unchecked /*&& item->isEnabled()*/) {
        // item->setEnabled(false);
        emit moleculeStateChanged(mol);
      }
      emit dataChanged(idx, idx);
      return true;
    case Qt::EditRole:
      if (!value.toString().isEmpty()) {
        // don't set an empty name
        mol->setData("name", std::string(value.toString().toLatin1()));
        emit dataChanged(idx, idx);
      }
      return true;
  }
  return false;
}

QVariant MoleculeModel::data(const QModelIndex& idx, int role) const
{
  if (!idx.isValid() || idx.column() > 2)
    return QVariant();

  auto* object = static_cast<QObject*>(idx.internalPointer());
  auto* mol = qobject_cast<Molecule*>(object);

  if (idx.row() == m_molecules.size()) {
    if (idx.column() == 0 && role == Qt::DecorationRole) {
      return m_plusIcon;
    }
    return QVariant();
  }

  if (!mol)
    return QVariant();

  if (idx.column() == 0) {
    switch (role) {
      case Qt::DisplayRole: {
        std::string name = tr("Untitled").toStdString();
        if (mol && mol->hasData("name") &&
            !(mol->data("name").toString().empty())) {
          // don't set an empty name
          name = mol->data("name").toString();
        } else if (mol && mol->hasData("fileName")) {
          name = QFileInfo(mol->data("fileName").toString().c_str())
                   .fileName()
                   .toStdString();
        }
        if (mol)
          return QString("%1 (%2)")
            .arg(QString::fromStdString(name))
            .arg(mol->formattedFormula());
        else
          return tr("Edit molecule");
      }
      case Qt::EditRole:
        return mol->data("name").toString().c_str();
      case Qt::ToolTipRole:
        if (mol->hasData("fileName"))
          return mol->data("fileName").toString().c_str();
        return tr("Not saved");
      case Qt::WhatsThisRole:
        return mol->formula().c_str();
      case Qt::ForegroundRole:
        if (mol == m_activeMolecule)
          return QVariant(QColor(Qt::red));
        else {
          const QPalette defaultPalette;
          return QVariant(defaultPalette.color(QPalette::WindowText));
        }
      default:
        return QVariant();
    }
  } else if (idx.column() == 1) {
    if (role == Qt::DecorationRole)
      return m_closeIcon;
  }
  return QVariant();
}

QModelIndex MoleculeModel::index(int row, int column,
                                 const QModelIndex& p) const
{
  if (!p.isValid())
    if (row >= 0 && row < m_molecules.size()) {
      return createIndex(row, column, m_molecules[row]);
    }
  if (row == m_molecules.size()) {
    return createIndex(row, column, nullptr);
  }
  return QModelIndex();
}

void MoleculeModel::clear()
{
  m_molecules.clear();
}

QList<Molecule*> MoleculeModel::molecules() const
{
  return m_molecules;
}

QList<Molecule*> MoleculeModel::activeMolecules() const
{
  QList<Molecule*> result;
  foreach (Molecule* mol, m_molecules) {
    if (true)
      result << mol;
  }
  return result;
}

void MoleculeModel::setActiveMolecule(QObject* active)
{
  if (m_activeMolecule == active)
    return;
  m_activeMolecule = active;
  emit dataChanged(createIndex(0, 0), createIndex(m_molecules.size(), 0));
}

void MoleculeModel::addItem(Molecule* item)
{
  if (!m_molecules.contains(item)) {
    int row = m_molecules.size();
    beginInsertRows(QModelIndex(), row, row);
    m_molecules.append(item);
    item->setParent(this);
    endInsertRows();
  }
}

void MoleculeModel::removeItem(Molecule* item)
{
  if (m_molecules.contains(item)) {
    int row = m_molecules.indexOf(item);
    beginRemoveRows(QModelIndex(), row, row);
    m_molecules.removeAt(row);
    // Do we want strong ownership of molecules?
    item->deleteLater();
    endRemoveRows();
  }
}

void MoleculeModel::itemChanged()
{
  auto* item = qobject_cast<Molecule*>(sender());
  if (item) {
    int row = m_molecules.indexOf(item);
    if (row >= 0)
      emit dataChanged(createIndex(row, 0), createIndex(row, 0));
  }
}

} // namespace Avogadro::QtGui

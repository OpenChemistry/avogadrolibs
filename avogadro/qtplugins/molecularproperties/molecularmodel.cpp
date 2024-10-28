/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularmodel.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/residue.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QDebug>
#include <QtCore/QRegularExpression>
#include <QtCore/QTimer>

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

#include <limits>

namespace Avogadro {

using Avogadro::QtGui::Molecule;
using QtGui::Molecule;

MolecularModel::MolecularModel(QObject* parent)
  : QAbstractTableModel(parent), m_molecule(nullptr)
{
  m_network = new QNetworkAccessManager(this);
  connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
          SLOT(updateNameReady(QNetworkReply*)));
}

void MolecularModel::setMolecule(QtGui::Molecule* molecule)
{
  m_molecule = molecule;
  // check if it has a pre-defined name
  if (molecule) {
    if (m_molecule->data("name").toString().empty())
      m_autoName = true;
    else
      m_autoName = false;
    m_name = QString::fromStdString(molecule->data("name").toString());
  }
}

QString MolecularModel::name() const
{
  // if we have a defined name
  // or we're not ready to update
  // then return the current name
  if (!m_autoName || m_nameRequestPending)
    return m_name;

  if (!m_molecule || m_molecule->atomCount() == 0)
    return m_name; // empty

  // okay, kick off the update
  m_name = tr("(pending)", "asking server for molecule name");
  m_nameRequestPending = true;

  std::string smiles;
  Io::FileFormatManager::instance().writeString(*m_molecule, smiles, "smi");
  QString smilesString = QString::fromStdString(smiles);
  smilesString.remove(QRegularExpression("\\s+.*"));
  QString requestURL =
    QString("https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/smiles/" +
            QUrl::toPercentEncoding(smilesString) + "/json");
  m_network->get(QNetworkRequest(QUrl(requestURL)));

  // don't update again until we're ready - 5 seconds
  QTimer::singleShot(5000, this, SLOT(canUpdateName()));

  return m_name;
}

void MolecularModel::canUpdateName()
{
  m_nameRequestPending = false;
}

void MolecularModel::updateNameReady(QNetworkReply* reply)
{
  // Read in all the data
  if (!reply->isReadable()) {
    reply->deleteLater();
    m_name = tr("unknown molecule");
    return;
  }

  // check if the data came through
  QByteArray data = reply->readAll();
  if (data.contains("Error report") || data.contains("<h1>")) {
    reply->deleteLater();
    m_name = tr("unknown molecule");
    return;
  }

  // parse the JSON
  // https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/smiles/…/json

  // PC_Compounds[0].props
  // iterate // get "urn" / "name" == "Markup" and "Preferred"
  //    ..       get "value" / "sval"

  QJsonDocument doc = QJsonDocument::fromJson(data);
  QJsonObject obj = doc.object();
  QJsonArray array = obj["PC_Compounds"].toArray();
  if (array.isEmpty()) {
    reply->deleteLater();
    m_name = tr("unknown molecule");
    return;
  }
  obj = array.first().toObject();
  array = obj["props"].toArray(); // props is an array of objects
  for (const QJsonValue& value : array) {
    obj = value.toObject();
    QJsonObject urn = obj["urn"].toObject();

    if (urn["name"].toString() == "Markup") {
      // HTML version for dialog
      QJsonObject nameValue = obj["value"].toObject();
      m_name = nameValue["sval"].toString();
    } else if (urn["name"].toString() == "Preferred") {
      // save this text version for files and copy/paste
      QJsonObject nameValue = obj["value"].toObject();
      m_molecule->setData("name", nameValue["sval"].toString().toStdString());
      m_name = nameValue["sval"].toString();
    }
  }

  emit dataChanged(index(Name, 0), index(Name, 0));

  reply->deleteLater();
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

QString formatFormula(Molecule* molecule)
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
  int charge = molecule->totalCharge();
  if (charge < 0)
    formula += QString("<sup>%1</sup>").arg(charge);
  else if (charge > 0)
    formula += QString("<sup>+%1</sup>").arg(charge);

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
    return this->name();
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

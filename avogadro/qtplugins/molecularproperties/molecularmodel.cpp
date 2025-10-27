/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularmodel.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/gaussianset.h>
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

using Avogadro::Core::BasisSet;
using Avogadro::Core::GaussianSet;
using Avogadro::QtGui::Molecule;
using QtGui::Molecule;

// CODATA 2022
// https://physics.nist.gov/cgi-bin/cuu/Value?hrev
#define AU_TO_EV 27.211386245981

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

  // make sure we know if the molecule changed
  connect(m_molecule, &QtGui::Molecule::changed, this,
          &MolecularModel::updateTable);
  updateTable(QtGui::Molecule::Added);
}

QString MolecularModel::name() const
{
  if (!m_molecule || m_molecule->atomCount() == 0)
    return m_name; // empty

  // if we have a defined name
  // or we're not ready to update
  // then return the current name
  if (!m_autoName || !m_nameUpdateNeeded || m_nameRequestPending)
    return m_name;

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
  // finished a request, don't need this until next modification
  m_nameUpdateNeeded = false;

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

  return m_propertiesCache.size();
}

int MolecularModel::columnCount(const QModelIndex& parent) const
{
  Q_UNUSED(parent);
  return 1; // values
}

QString formatPointGroup(std::string pointgroup)
{
  // first character is in capital
  // then everything else is in subscript using <sub>...</sub>
  QString formatted = QString::fromStdString(pointgroup);
  QString output = formatted.at(0).toUpper();
  output += QString("<sub>%1</sub>").arg(formatted.mid(1));
  return output;
}

// Qt calls this for multiple "roles" across row / columns in the index
//   we also combine multiple types into this class, so lots of special cases
QVariant MolecularModel::data(const QModelIndex& index, int role) const
{
  if (!index.isValid() || m_molecule == nullptr)
    return QVariant();

  int row = index.row();
  [[maybe_unused]] int col = index.column();

  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    return toVariant(Qt::AlignRight);
  }

  if (role != Qt::UserRole && role != Qt::DisplayRole && role != Qt::EditRole)
    return QVariant();

  const auto map = m_propertiesCache;
  auto it = map.begin();

  switch (row) {
    case 0:
      return name();
    case 1:
      return m_molecule->mass();
    case 2:
      return m_molecule->formattedFormula();
    case 3:
      return QVariant::fromValue(m_molecule->atomCount());
    case 4:
      return QVariant::fromValue(m_molecule->bondCount());
  }

  std::advance(it, row);
  auto key = it->first;
  if (key == " 6coordinateSets")
    return QVariant::fromValue(m_molecule->coordinate3dCount());
  else if (key == " 7residues")
    return QVariant::fromValue(m_molecule->residueCount());
  else if (key == " 9totalCharge")
    return QVariant::fromValue(static_cast<int>(m_molecule->totalCharge()));
  else if (key == " 9totalSpinMultiplicity")
    return QVariant::fromValue(
      static_cast<int>(m_molecule->totalSpinMultiplicity()));
  else if (key == "pointgroup")
    return formatPointGroup(it->second.toString());

  return QString::fromStdString(it->second.toString());
}

QVariant MolecularModel::headerData(int section, Qt::Orientation orientation,
                                    int role) const
{
  // Simple lambda to convert QFlags to variant as in Qt 6 this needs help.
  auto toVariant = [&](auto flags) {
    return static_cast<Qt::Alignment::Int>(flags);
  };

  // handle text alignments
  if (role == Qt::TextAlignmentRole) {
    if (orientation == Qt::Vertical) {
      return toVariant(Qt::AlignLeft);
    }
    return toVariant(Qt::AlignHCenter);
  }

  if (role != Qt::DisplayRole)
    return QVariant();

  if (orientation == Qt::Horizontal) {
    return tr("Property");
  } else if (orientation == Qt::Vertical) {

    const auto map = m_propertiesCache;
    auto it = map.begin();
    std::advance(it, section);
    if (it->first == " 1name")
      return tr("Molecule Name");
    else if (it->first == " 2mass")
      return tr("Molecular Mass (g/mol)");
    else if (it->first == " 3formula")
      return tr("Chemical Formula");
    else if (it->first == " 4atoms")
      return tr("Number of Atoms");
    else if (it->first == " 5bonds")
      return tr("Number of Bonds");
    else if (it->first == " 6coordinateSets")
      return tr("Coordinate Sets");
    else if (it->first == " 7residues")
      return tr("Number of Residues");
    else if (it->first == " 8chains")
      return tr("Number of Chains");
    else if (it->first == " 9totalCharge")
      return tr("Net Charge");
    else if (it->first == " 9totalSpinMultiplicity")
      return tr("Net Spin Multiplicity");
    else if (it->first == "dipoleMoment")
      return tr("Dipole Moment (Debye)");
    else if (it->first == "homoEnergy")
      return tr("HOMO Energy (eV)", "highest occupied molecular orbital");
    else if (it->first == "lumoEnergy")
      return tr("LUMO Energy (eV)", "lowest unoccupied molecular orbital");
    else if (it->first == "somoEnergy")
      return tr("SOMO Energy (eV)", "singly-occupied molecular orbital");
    else if (it->first == "totalEnergy")
      return tr("Total Energy (Hartree)",
                "total electronic energy in Hartrees");
    else if (it->first == "zpe")
      return tr("Zero Point Energy (kcal/mol)",
                "zero point vibrational energy");
    else if (it->first == "enthalpy")
      return tr("Enthalpy (kcal/mol)");
    else if (it->first == "entropy")
      return tr("Entropy (kcal/mol•K)");
    else if (it->first == "gibbs")
      return tr("Gibbs Free Energy (kcal/mol)");
    else if (it->first == "pointgroup")
      return tr("Point Group", "point group symmetry");
    else if (it != map.end())
      return QString::fromStdString(it->first);

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

  int row = index.row();

  if (row == 0) // name
    return editable;

  const auto map = m_propertiesCache;
  auto it = map.begin();
  std::advance(it, row);
  auto key = it->first;
  if (key == " 9totalCharge" || key == " 9totalSpinMultiplicity")
    return editable;

  return QAbstractItemModel::flags(index);
}

bool MolecularModel::setData(const QModelIndex& index, const QVariant& value,
                             int role)
{
  if (!index.isValid())
    return false;

  if (role != Qt::EditRole)
    return false;

  int row = index.row();

  if (row == 0) { // name should always be the first row
    m_name = value.toString();
    m_autoName = false;
    m_molecule->setData("name", m_name.toStdString());
    emit dataChanged(index, index);
    return true;
  }

  const auto map = m_propertiesCache;
  auto it = map.begin();
  std::advance(it, row);
  auto key = it->first;
  if (key == " 9totalCharge") {
    m_molecule->setData("totalCharge", value.toInt());
    emit dataChanged(index, index);
    return true;
  } else if (key == " 9totalSpinMultiplicity") {
    int spin = value.toInt();
    if (spin < 1)
      return false;

    m_molecule->setData("totalSpinMultiplicity", value.toInt());
    emit dataChanged(index, index);
    return true;
  }

  return false;
}

void MolecularModel::updateTable(unsigned int flags)
{
  // cache all the properties
  m_propertiesCache.clear();
  if (m_molecule == nullptr)
    return;

  m_nameUpdateNeeded = true;

  // we use internal key names here and
  // update the display names in the headerData method
  m_propertiesCache.setValue(" 1name", name());
  m_propertiesCache.setValue(" 2mass", m_molecule->mass());
  m_propertiesCache.setValue(" 3formula", m_molecule->formattedFormula());
  m_propertiesCache.setValue(" 4atoms", m_molecule->atomCount());
  m_propertiesCache.setValue(" 5bonds", m_molecule->bondCount());
  if (m_molecule->coordinate3dCount() > 0)
    m_propertiesCache.setValue(" 6coordinateSets",
                               m_molecule->coordinate3dCount());
  if (m_molecule->residueCount() > 0) {
    m_propertiesCache.setValue(" 7residues", m_molecule->residueCount());

    // figure out if we have multiple chains
    unsigned int chainCount = 0;
    unsigned int offset = 0;
    for (Index i = 0; i < m_molecule->residueCount(); ++i) {
      char chainId = m_molecule->residue(i).chainId();
      if (chainId >= 'A' && chainId <= 'Z')
        offset = chainId - 'A';
      else if (chainId >= 'a' && chainId <= 'z')
        offset = chainId - 'a';
      else if (chainId >= '0' && chainId <= '9')
        offset = chainId - '0' + 15; // starts at 'P'

      chainCount = std::max(chainCount, offset);
    }
    m_propertiesCache.setValue(" 8chains", chainCount);
  }

  m_propertiesCache.setValue(" 9totalCharge",
                             static_cast<int>(m_molecule->totalCharge()));
  m_propertiesCache.setValue(
    " 9totalSpinMultiplicity",
    static_cast<int>(m_molecule->totalSpinMultiplicity()));
  if (m_molecule->hasData("dipoleMoment")) {
    auto dipole = m_molecule->data("dipoleMoment").toVector3();
    QString moment = QString::number(dipole.norm(), 'f', 3);
    m_propertiesCache.setValue("dipoleMoment", moment.toStdString());
  }

  // TODO check for homo, lumo, or somo energies
  const auto* basis = m_molecule->basisSet();
  const GaussianSet* gaussianSet = dynamic_cast<const GaussianSet*>(basis);
  if (gaussianSet != nullptr && gaussianSet->scfType() == Core::Rhf) {
    unsigned int homo = gaussianSet->homo();
    unsigned int lumo = gaussianSet->lumo();
    const auto moEnergies = gaussianSet->moEnergy();
    if (moEnergies.size() > homo) {
      m_propertiesCache.setValue("homoEnergy", moEnergies[homo] * AU_TO_EV);
    }
    // look for the lumo if there's a degenerate HOMO
    const double threshold = 0.01 / AU_TO_EV; // 0.01 eV minimal separation
    while (moEnergies.size() > lumo &&
           std::abs(moEnergies[lumo] - moEnergies[homo]) < threshold) {
      lumo += 1;
    }
    if (moEnergies.size() > lumo)
      m_propertiesCache.setValue("lumoEnergy", moEnergies[lumo] * AU_TO_EV);
  }
  // m_propertiesCache.setValue("somoEnergy", energy);

  // ignore potentially duplicate properties
  const auto& properties = m_molecule->dataMap();
  for (const auto& key : properties.names()) {
    if (key == "formula" || key == "name" || key == "fileName" ||
        key == "energies" || key == "totalCharge" ||
        key == "totalSpinMultiplicity")
      continue; // skip these

    if (properties.value(key).toString().empty())
      continue; // don't bother with an empty value

    m_propertiesCache.setValue(key, properties.value(key));
  }

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

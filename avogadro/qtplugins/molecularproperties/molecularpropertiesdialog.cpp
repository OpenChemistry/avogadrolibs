/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularpropertiesdialog.h"
#include "ui_molecularpropertiesdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>
#include <QtCore/QRegExp>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

using Avogadro::QtGui::Molecule;

namespace Avogadro::QtPlugins {

MolecularPropertiesDialog::MolecularPropertiesDialog(QtGui::Molecule* mol,
                                                     QWidget* parent_)
  : QDialog(parent_), m_molecule(nullptr),
    m_ui(new Ui::MolecularPropertiesDialog)
{
  m_ui->setupUi(this);

  m_network = new QNetworkAccessManager(this);
  connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
          SLOT(replyFinished(QNetworkReply*)));

  setMolecule(mol);
}

MolecularPropertiesDialog::~MolecularPropertiesDialog()
{
  delete m_ui;
}

void MolecularPropertiesDialog::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (!m_molecule)
    return;

  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateLabels()));
  connect(m_molecule, SIGNAL(destroyed()), SLOT(moleculeDestroyed()));
  updateLabels();
}

void MolecularPropertiesDialog::updateLabels()
{
  if (m_molecule) {
    updateMassLabel();
    updateFormulaLabel();
    updateName();
    m_ui->atomCountLabel->setText(QString::number(m_molecule->atomCount()));
    m_ui->bondCountLabel->setText(QString::number(m_molecule->bondCount()));
  } else {
    m_ui->molMassLabel->clear();
    m_ui->formulaLabel->clear();
    m_ui->atomCountLabel->clear();
    m_ui->bondCountLabel->clear();
  }
}

void MolecularPropertiesDialog::updateName()
{
  QString name = tr("(pending)", "asking server for molecule name");

  if (!m_molecule || m_molecule->atomCount() == 0) {
    m_ui->moleculeNameLabel->clear();
    return;
  }

  m_ui->moleculeNameLabel->setText(name); // while we wait

  // InChI is intentionally designed to avoid issues with URL encoding
  std::string smiles;
  Io::FileFormatManager::instance().writeString(*m_molecule, smiles, "smi");
  QString smilesString = QString::fromStdString(smiles);
  smilesString.remove(QRegExp("\\s+.*"));
  QString requestURL =
    QString("https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/smiles/" +
            QUrl::toPercentEncoding(smilesString) + "/json");

  // qDebug() << "Requesting" << requestURL;

  m_network->get(QNetworkRequest(QUrl(requestURL)));
}

void MolecularPropertiesDialog::replyFinished(QNetworkReply* reply)
{
  // Read in all the data
  if (!reply->isReadable()) {
    reply->deleteLater();
    m_ui->moleculeNameLabel->setText(tr("unknown molecule"));
    return;
  }

  // check if the data came through
  QByteArray data = reply->readAll();
  if (data.contains("Error report") || data.contains("<h1>")) {
    reply->deleteLater();
    m_ui->moleculeNameLabel->setText(tr("unknown molecule"));
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
    m_ui->moleculeNameLabel->setText(tr("unknown molecule"));
    return;
  }
  obj = array.first().toObject();
  array = obj["props"].toArray(); // props is an array of objects
  for (const QJsonValue& value : array) {
    obj = value.toObject();
    QJsonObject urn = obj["urn"].toObject();

    if (urn["name"].toString() == "Markup") {
      QJsonObject value = obj["value"].toObject();
      m_ui->moleculeNameLabel->setText(value["sval"].toString());
      break;
    }
  }

/*
  QString name = QString(data).trimmed().toLower();
  if (!name.isEmpty()) {
    m_ui->moleculeNameLabel->setText(name);
    // TODO: set the name in the molecule
  } else {
    m_ui->moleculeNameLabel->setText(tr("unknown molecule"));
  }
  */

  reply->deleteLater();
}

void MolecularPropertiesDialog::updateMassLabel()
{
  double mass = 0.0;
  for (size_t i = 0; i < m_molecule->atomCount(); ++i)
    mass += Core::Elements::mass(m_molecule->atom(i).atomicNumber());
  m_ui->molMassLabel->setText(QString::number(mass, 'f', 3));
}

void MolecularPropertiesDialog::updateFormulaLabel()
{
  QString formula = QString::fromStdString(m_molecule->formula());
  QRegExp digitParser("(\\d+)");

  int ind = digitParser.indexIn(formula);
  while (ind != -1) {
    QString digits = digitParser.cap(1);
    formula.replace(ind, digits.size(), QString("<sub>%1</sub>").arg(digits));
    ind = digitParser.indexIn(formula, ind + digits.size() + 11);
  }

  m_ui->formulaLabel->setText(formula);
}

void MolecularPropertiesDialog::moleculeDestroyed()
{
  m_molecule = nullptr;
  updateLabels();
}

} // namespace Avogadro::QtPlugins

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "molecularproperties.h"
#include "molecularmodel.h"
#include "molecularview.h"

#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/richtextdelegate.h>

#include <QAction>
#include <QStringList>
#include <QtCore/QRegularExpression>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QJsonValue>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QScrollBar>
#include <QtWidgets/QVBoxLayout>

using Avogadro::QtGui::RichTextDelegate;

namespace Avogadro::QtPlugins {

MolecularProperties::MolecularProperties(QObject* parent_)
  : Avogadro::QtGui::ExtensionPlugin(parent_), m_action(new QAction(this)),
    m_molecule(nullptr), m_dialog(nullptr), m_model(nullptr),
    m_network(new QNetworkAccessManager(this))
{
  m_action->setEnabled(true);
  m_action->setText(tr("&Molecular…"));
  m_action->setProperty("menu priority", 990);

  connect(m_action, SIGNAL(triggered()), SLOT(showDialog()));
  connect(m_network, SIGNAL(finished(QNetworkReply*)), this,
          SLOT(updateNameReady(QNetworkReply*)));
}

MolecularProperties::~MolecularProperties() {}

QString MolecularProperties::description() const
{
  return tr("View general properties of a molecule.");
}

QList<QAction*> MolecularProperties::actions() const
{
  return QList<QAction*>() << m_action;
}

QStringList MolecularProperties::menuPath(QAction*) const
{
  return QStringList() << tr("&Analyze") << tr("&Properties");
}

void MolecularProperties::setMolecule(QtGui::Molecule* mol)
{
  if (mol == m_molecule)
    return;

  // Cancel any pending network request to avoid applying the wrong name
  if (m_nameRequestPending && m_pendingReply != nullptr) {
    m_pendingReply->abort();
    m_pendingReply = nullptr;
    m_nameRequestPending = false;
  }

  // Disconnect from the old molecule if set
  if (m_molecule) {
    disconnect(m_molecule, &QtGui::Molecule::changed, this,
               &MolecularProperties::updateName);
  }

  m_molecule = mol;

  if (m_molecule) {
    connect(m_molecule, &QtGui::Molecule::changed, this,
            &MolecularProperties::updateName);
    updateName();
  }
}

void MolecularProperties::updateName(bool checkDialog)
{
  if (!m_molecule || m_molecule->atomCount() == 0)
    return;

  // only update the name if the dialog is open
  if (checkDialog && (m_dialog == nullptr || !m_dialog->isVisible()))
    return;

  // don't send multiple requests
  if (m_nameRequestPending)
    return;

  m_nameRequestPending = true;

  qDebug() << "Updating name";

  if (m_molecule != nullptr)
    m_molecule->setData("name", tr("(pending)"));

  std::string smiles;
  Io::FileFormatManager::instance().writeString(*m_molecule, smiles, "smi");
  QString smilesString = QString::fromStdString(smiles);
  smilesString.remove(QRegularExpression("\\s+.*"));
  QString requestURL =
    QString("https://pubchem.ncbi.nlm.nih.gov/rest/pug/compound/smiles/" +
            QUrl::toPercentEncoding(smilesString) + "/json");
  m_pendingReply = m_network->get(QNetworkRequest(QUrl(requestURL)));
}

void MolecularProperties::updateNameReady(QNetworkReply* reply)
{
  m_nameRequestPending = false;
  m_pendingReply = nullptr;

  // Check if request was aborted or had network error
  if (reply->error() != QNetworkReply::NoError || !reply->isReadable()) {
    reply->deleteLater();
    return;
  }

  // Read in all the data
  // and check if the data came through
  QByteArray data = reply->readAll();
  if (data.contains("Error report") || data.contains("<h1>")) {
    reply->deleteLater();
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
    return;
  }
  obj = array.first().toObject();
  array = obj["props"].toArray(); // props is an array of objects
  for (const QJsonValue& value : array) {
    obj = value.toObject();
    QJsonObject urn = obj["urn"].toObject();

    if (urn["name"].toString() == "Preferred") {
      // save this text version for files and copy/paste
      QJsonObject nameValue = obj["value"].toObject();
      if (m_molecule != nullptr)
        m_molecule->setData("name", nameValue["sval"].toString().toStdString());
    }
    if (urn["name"].toString() == "Markup") {
      // HTML version for dialog
      QJsonObject nameValue = obj["value"].toObject();
      if (m_molecule != nullptr)
        m_molecule->setData("markup_name",
                            nameValue["sval"].toString().toStdString());
    }
  }
  // tell the model to update
  if (m_model != nullptr)
    m_model->dataChanged(m_model->index(0, 0), m_model->index(0, 0));

  reply->deleteLater();
}

void MolecularProperties::showDialog()
{
  if (m_dialog == nullptr) {
    // create it
    // copied from the propeties dialog
    m_dialog = new QDialog(qobject_cast<QWidget*>(parent()));
    auto* layout = new QVBoxLayout(m_dialog);
    m_dialog->setLayout(layout);
    // Don't show whitespace around the table view
    layout->setSpacing(0);
    layout->setContentsMargins(0, 0, 0, 0);

    m_model = new MolecularModel();
    // check if the molecule has a name.. if not indicate pending
    if (m_molecule != nullptr && !m_molecule->hasData("name")) {
      m_molecule->setData("name", tr("(pending)"));
    }
    m_model->setMolecule(m_molecule);
    // view will delete itself & model using deleteLater()
    auto* view = new MolecularView(m_dialog);
    view->setMolecule(m_molecule);
    view->setSourceModel(m_model);
    view->setModel(m_model);

    // set the headers to true
    QFont font = view->horizontalHeader()->font();
    font.setBold(true);
    view->horizontalHeader()->setFont(font);
    view->verticalHeader()->setFont(font);

    view->setItemDelegateForColumn(0, new RichTextDelegate(view));

    view->horizontalHeader()->setStretchLastSection(true);
    view->resizeColumnsToContents();

    layout->addWidget(view);

    m_dialog->setWindowTitle(view->windowTitle());
    m_dialog->setWindowFlags(Qt::Window);
  }

  // update the name before we show the dialog
  if (m_molecule != nullptr)
    updateName(false); // we don't want to check the dialog

  m_dialog->show();
  m_dialog->raise();
}

} // namespace Avogadro::QtPlugins

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_NETWORKDATABASES_H
#define AVOGADRO_QTPLUGINS_NETWORKDATABASES_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/avogadrocore.h>

#include <QtCore/QString>

class QNetworkAccessManager;
class QNetworkReply;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Queries online databases (currently the NIH structure resolver) and
 * loads the returned structure if one is found.
 */

class NetworkDatabases : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit NetworkDatabases(QObject* parent = nullptr);
  ~NetworkDatabases() override;

  QString name() const override { return tr("Network Databases"); }

  QString description() const override
  {
    return tr("Interact with online databases, query structures etc.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void showDialog();
  void replyFinished(QNetworkReply*);

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  QNetworkAccessManager* m_network;
  QString m_moleculeName;
  QByteArray m_moleculeData;
  QProgressDialog* m_progressDialog;
};
}
}

#endif // AVOGADRO_QTPLUGINS_NETWORKDATABASES_H

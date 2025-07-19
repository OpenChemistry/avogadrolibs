/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_IMPORTPQR_H
#define AVOGADRO_QTPLUGINS_IMPORTPQR_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/io/fileformatmanager.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>

#include <QtCore/QString>

class QAction;
class QDialog;

namespace Avogadro {

namespace QtPlugins {

class PQRWidget;

class ImportPQR : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit ImportPQR(QObject* parent = nullptr);
  ~ImportPQR() override;

  QString name() const override { return tr("Import From PQR"); }

  QString description() const override
  {
    return tr("Download a molecule from PQR.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMoleculeData(QByteArray& molData, QString name);

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();
  void checkAccess(QNetworkReply* reply);

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  PQRWidget* m_dialog;
  const Io::FileFormat* m_outputFormat;
  QString m_moleculeName;
  QString m_moleculePath;
  QByteArray m_moleculeData;
  QNetworkAccessManager* m_manager;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_IMPORTPQR_H

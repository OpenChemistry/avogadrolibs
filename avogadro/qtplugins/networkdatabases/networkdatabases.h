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

  void registerCommands() override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  bool readMolecule(QtGui::Molecule& mol) override;
  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

private slots:
  void showDialog();
  void replyFinished(QNetworkReply*);

private:
  static bool sdfHasThreeDCoordinates(const QByteArray& data);

  /// Starts (or restarts, for the PubChem retry) the network request for
  /// @p structureName. Shared by showDialog() and the fetchByName command.
  void requestStructure(const QString& structureName);

  /// If a fetchByName command is pending, clears m_commandPending and emits
  /// commandFinished() with the resolved @p name and the @p source that
  /// answered ("cactus" or "pubchem"). No-op when not command-driven.
  void reportCommandSuccess(const QString& name, const QString& source);

  QAction* m_action;
  QtGui::Molecule* m_molecule;
  QNetworkAccessManager* m_network;
  QString m_moleculeName;
  QByteArray m_moleculeData;
  QProgressDialog* m_progressDialog;
  bool m_triedPubChem = false;
  /// True while a fetchByName command is waiting on a download, so that
  /// replyFinished() reports through commandFinished()/commandFailed()
  /// instead of the interactive dialogs. Mirrors Surfaces::m_commandPending.
  bool m_commandPending = false;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_NETWORKDATABASES_H

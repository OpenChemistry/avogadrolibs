/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FETCHPDB_H
#define AVOGADRO_QTPLUGINS_FETCHPDB_H

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

class FetchPDB : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit FetchPDB(QObject* parent = nullptr);
  ~FetchPDB() override;

  QString name() const override { return tr("Fetch from PDB"); }

  QString description() const override
  {
    return tr("Download PDB models from the Protein Data Bank");
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
  /// Checks @p pdbCode against the Protein Data Bank identifier format: four
  /// characters, the first a digit 1-9, the rest ASCII letters or digits.
  /// Writes the reason for a rejection to @p error when it is not null.
  /// Shared by showDialog() and the fetchPDB command so both reject the
  /// same codes for the same reasons.
  static bool isValidPdbCode(const QString& pdbCode, QString* error);

  /// Starts the download of @p pdbCode from RCSB, stamping the reply with
  /// the code, the suffix used and @p commandDriven so that replyFinished()
  /// can tell which request landed. Shared by showDialog() (false) and the
  /// fetchPDB command (true).
  void requestStructure(const QString& pdbCode, bool commandDriven);

  /// Reports @p message through commandFailed() when a fetchPDB command is
  /// waiting on the download, and through a warning box titled @p title
  /// otherwise. Clears m_commandPending in the command case.
  void reportFailure(const QString& title, const QString& message);

  /// If a fetchPDB command is pending, clears m_commandPending and emits
  /// commandFinished() with the @p pdbCode that was downloaded. No-op when
  /// not command-driven.
  void reportCommandSuccess(const QString& pdbCode);

  QAction* m_action;
  QtGui::Molecule* m_molecule;
  QNetworkAccessManager* m_network;
  QString m_moleculeName;
  QByteArray m_moleculeData;
  QProgressDialog* m_progressDialog;
  QString m_tempFileName;
  /// The suffix of the download being handled: ".pdb.gz" where gzip can be
  /// decoded, ".pdb" otherwise. Set on the request and read back off the
  /// reply, so the URL and the temporary file name cannot drift apart even
  /// when two downloads overlap.
  QString m_downloadSuffix{ QStringLiteral(".pdb") };
  /// True while the download being handled belongs to a fetchPDB command, so
  /// that replyFinished() reports through commandFinished()/commandFailed()
  /// instead of the interactive dialogs. Re-established from the reply at the
  /// top of replyFinished() rather than trusted from the last request, since
  /// readMolecule() is called out of band and can only see the members.
  bool m_commandPending = false;
  /// Set by readMolecule(), which MainWindow calls synchronously from
  /// moleculeReady() without passing its result back to us.
  bool m_lastReadOk = false;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_FETCHPDB_H

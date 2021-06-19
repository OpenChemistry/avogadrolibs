/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_COMMAND_H
#define AVOGADRO_QTPLUGINS_COMMAND_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>
#include <QtCore/QStringList>

class QAction;
class QDialog;
class QProgressDialog;

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace QtGui {
class InterfaceScript;
class InterfaceWidget;
}

namespace QtPlugins {

/**
 * @brief The Command class implements the extension interface for
 * external (script) Commands
 * @author Geoffrey R. Hutchison
 */
class Command : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Command(QObject* parent = nullptr);
  ~Command() override;

  QString name() const override { return tr("Command scripts"); }

  QString description() const override
  {
    return tr("Run external script commands");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Scan for new scripts in the command directories.
   */
  void refreshScripts();

  void run();

  bool readMolecule(QtGui::Molecule& mol) override;

  void processFinished();

private slots:
  void menuActivated();
  void configurePython();

private:
  void updateScripts();
  void updateActions();
  void addAction(const QString& label, const QString& scriptFilePath);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;
  // keyed on script file path
  QMap<QString, QtGui::InterfaceWidget*> m_dialogs;
  QDialog* m_currentDialog;
  QtGui::InterfaceWidget* m_currentInterface;
  QtGui::InterfaceScript* m_currentScript;
  QProgressDialog* m_progress;

  // maps program name --> script file path
  QMap<QString, QString> m_commandScripts;

  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};
}
}

#endif // AVOGADRO_QTPLUGINS_COMMAND_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OPENMMINPUT_H
#define AVOGADRO_QTPLUGINS_OPENMMINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace QtPlugins {

class OpenMMInputDialog;

class OpenMMInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit OpenMMInput(QObject* parent = nullptr);
  ~OpenMMInput() override;

  QString name() const override { return tr("OpenMM input"); }

  QString description() const override
  {
    return tr("Generate input for OpenMM.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  // void openJobOutput(const MoleQueue::JobObject& job);

  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  OpenMMInputDialog* m_dialog;
  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OPENMMINPUT_H

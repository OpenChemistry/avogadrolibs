/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CP2KINPUT_H
#define AVOGADRO_QTPLUGINS_CP2KINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

class QAction;
class QDialog;

namespace Avogadro {
namespace Io {
class FileFormat;
}
namespace MoleQueue {
class JobObject;
}

namespace QtPlugins {

class Cp2kInputDialog;

class Cp2kInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit Cp2kInput(QObject* parent = nullptr);
  ~Cp2kInput() override;

  QString name() const override { return tr("CP2K input"); }

  QString description() const override
  {
    return tr("Generate input for CP2K.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const Avogadro::MoleQueue::JobObject& job);

  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void menuActivated();

private:
  QAction* m_action;
  QtGui::Molecule* m_molecule;
  Cp2kInputDialog* m_dialog;
  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CP2KINPUT_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_QUANTUMINPUT_H
#define AVOGADRO_QTPLUGINS_QUANTUMINPUT_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMap>
#include <QtCore/QMultiHash>
#include <QtCore/QVariantMap>

class QAction;
class QDialog;

namespace Avogadro {
namespace Io {
class FileFormat;
}

namespace MoleQueue {
class InputGeneratorDialog;
class JobObject;
} // namespace MoleQueue

namespace QtPlugins {

/**
 * @brief The QuantumInput class implements the extension interface for
 * simulation input generators.
 * @author Allison Vacanti
 */
class QuantumInput : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit QuantumInput(QObject* parent = nullptr);
  ~QuantumInput() override;

  QString name() const override { return tr("Quantum input"); }

  QString description() const override
  {
    return tr("Generate input for quantum codes.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Scan for new scripts in the input generator directories.
   */
  void refreshGenerators();

  /**
   * Emitted when the user requests that a job's output be loaded in Avogadro.
   */
  void openJobOutput(const MoleQueue::JobObject& job);

  bool readMolecule(QtGui::Molecule& mol) override;

  /**
   * Handle a feature registered by PackageManager.
   */
  void registerFeature(const QString& type, const QString& packageDir,
                       const QString& command, const QString& identifier,
                       const QVariantMap& metadata);

  /**
   * Handle a feature removed by PackageManager.
   */
  void unregisterFeature(const QString& type, const QString& packageDir,
                         const QString& command, const QString& identifier);

private slots:
  void menuActivated();
  void moleculeChanged(unsigned int change);

private:
  void updateActionStates();

  QtGui::Molecule* m_molecule;
  // keyed on package feature key
  QMap<QString, MoleQueue::InputGeneratorDialog*> m_dialogs;
  QMultiHash<QString, QAction*> m_packageActions;

  const Io::FileFormat* m_outputFormat;
  QString m_outputFileName;
};
} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_QUANTUMINPUT_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OPENBABEL_H
#define AVOGADRO_QTPLUGINS_OPENBABEL_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMultiMap>

class QAction;
class QProgressDialog;

namespace Avogadro {
namespace QtPlugins {

class OBProcess;

/**
 * @brief The OpenBabel class implements the ExtensionPlugin interface to
 * expose some OpenBabel functionality.
 *
 * @todo The readMolecule method will need to be updated if we allow
 * multimolecule files to load with the Io::CmlReader.
 */
class OpenBabel : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  explicit OpenBabel(QObject* parent = nullptr);
  ~OpenBabel() override;

  QString name() const override { return tr("OpenBabel"); }

  QString description() const override
  {
    return tr("Interact with OpenBabel utilities.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  QList<Io::FileFormat*> fileFormats() const override;

  QString openBabelInfo() const;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  bool readMolecule(QtGui::Molecule& mol) override;

private slots:
  void refreshReadFormats();
  void handleReadFormatUpdate(const QMultiMap<QString, QString>& fmts);

  void refreshWriteFormats();
  void handleWriteFormatUpdate(const QMultiMap<QString, QString>& fmts);

  void refreshForceFields();
  void handleForceFieldsUpdate(const QMultiMap<QString, QString>& ffMap);

  void refreshCharges();
  void handleChargesUpdate(const QMultiMap<QString, QString>& chargeMap);

  void onConfigureGeometryOptimization();

  void onOptimizeGeometry();
  void onOptimizeGeometryStatusUpdate(int step, int numSteps, double energy,
                                      double lastEnergy);
  void onOptimizeGeometryFinished(const QByteArray& output);

  void onPerceiveBonds();
  void onPerceiveBondsFinished(const QByteArray& output);

  void onAddHydrogens();
  void onAddHydrogensPh();
  void onRemoveHydrogens();
  void onHydrogenOperationFinished(const QByteArray& cml);

private:
  void initializeProgressDialog(const QString& title, const QString& label,
                                int min, int max, int value,
                                bool showDialog = true);
  void showProcessInUseError(const QString& title) const;
  QString autoDetectForceField() const;

  QtGui::Molecule* m_molecule;
  OBProcess* m_process;
  QList<QAction*> m_actions;
  QList<QByteArray> m_moleculeQueue;
  bool m_readFormatsPending;
  bool m_writeFormatsPending;
  QMultiMap<QString, QString> m_readFormats;
  QMultiMap<QString, QString> m_writeFormats;
  QMultiMap<QString, QString> m_forceFields;
  QMultiMap<QString, QString> m_charges;
  std::string m_defaultFormat;
  QProgressDialog* m_progress;
};
}
}

#endif // AVOGADRO_QTPLUGINS_OPENBABEL_H

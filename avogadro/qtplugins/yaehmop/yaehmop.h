/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_YAEHMOP_H
#define AVOGADRO_QTPLUGINS_YAEHMOP_H

#include "banddialog.h"
#include "yaehmopsettings.h"

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/vector.h>

#include <avogadro/qtgui/chartdialog.h>

#include <memory>

// Forward declarations
class QByteArray;

namespace Avogadro::QtPlugins {

/**
 * @brief Perform extended Hückel calculations with yaehmop.
 */
class Yaehmop : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Yaehmop(QObject* parent_ = nullptr);
  ~Yaehmop() override;

  QString name() const override { return tr("Yaehmop"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void displayBandDialog();

private:
  void readSettings();
  void writeSettings();

  // This pops up a dialog box with the yaehmop input inside
  void showYaehmopInput(const QString& input);

  // Get the distance between two k points
  double kpointDistance(const Avogadro::Vector3& a, const Avogadro::Vector3& b);

  void calculateBandStructure();

  QString createGeometryAndLatticeInput() const;

  // Use QProcess to execute yaehmop
  // If the YAEHMOP_EXECUTABLE environment variable is set, that will be
  // used for the executable. Otherwise, it will search for the executable in
  // some common places and use it if it can be found.
  bool executeYaehmop(const QByteArray& input, QByteArray& output,
                      QString& err);

  QString m_programPath;
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  YaehmopSettings m_yaehmopSettings;

  std::unique_ptr<BandDialog> m_bandDialog;
  std::unique_ptr<QAction> m_displayBandDialogAction;
  QScopedPointer<QtGui::ChartDialog> m_chartDialog;
};

inline QString Yaehmop::description() const
{
  return tr("Perform extended Hückel calculations with yaehmop.");
}

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_YAEHMOPEXTENSION_H

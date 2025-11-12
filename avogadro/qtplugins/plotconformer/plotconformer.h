/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTCONFORMER_H
#define AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QDialog>
#include <QComboBox>

#include <memory>

namespace Avogadro {

namespace QtGui {
class ChartWidget;
}

namespace QtPlugins {

using DataSeries = std::vector<float>;

/**
 * @brief Generate and plot conformer data (RMSD or energy)
 */
class PlotConformer : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit PlotConformer(QObject* parent_ = nullptr);
  ~PlotConformer() override;

  QString name() const override { return tr("PlotConformer"); }
  QString description() const override;
  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void displayDialog();
  void updatePlot();

  void clicked(float x, float y, Qt::KeyboardModifiers modifiers);

private:
  // Generate RMSD data from a coordinate set
  // Writes the results to @p x and @p y
  void generateRmsdCurve(DataSeries& x, DataSeries& y);

  // Generate a relative energy data from a coordinate set
  void generateEnergyCurve(DataSeries& x, DataSeries& y);

  // Generate a forces data from a coordinate set
  void generateForcesCurve(DataSeries& x, DataSeries& y);

  // Generate a velocities data from a coordinate set
  void generateVelocitiesCurve(DataSeries& x, DataSeries& y);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QAction* m_displayDialogAction;
  std::unique_ptr<QDialog> m_dialog;
  QtGui::ChartWidget* m_chartWidget;
  QComboBox* m_propertyCombo;
  QComboBox* m_unitsCombo;
  QComboBox* m_targetUnitsCombo;
};

inline QString PlotConformer::description() const
{
  return tr("Generate and plot conformer data (RMSD or energy).");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

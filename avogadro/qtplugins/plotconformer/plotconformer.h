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

class QLabel;

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

  /**
   * Arrow keys, page up/down and home/end step through the conformers while
   * the plot dialog is focused.
   */
  bool eventFilter(QObject* object, QEvent* event) override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void displayDialog();
  void updatePlot();

  void clicked(float x, float y, Qt::KeyboardModifiers modifiers);

private:
  // Show conformer @p frame, clamped to the available coordinate sets, and
  // tell the rest of the application about it.
  void setFrame(int frame);

  // Redraw the cached curve plus the marker for the current conformer. Cheap
  // enough to call on every arrow key, unlike updatePlot().
  void drawChart();

  // Fill the plot type combo with whatever the current molecule offers.
  void populatePropertyCombo();

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
  QLabel* m_frameLabel;
  DataSeries m_xData;
  DataSeries m_yData;
  QString m_yTitle;
  int m_currentFrame = 0;
};

inline QString PlotConformer::description() const
{
  return tr("Generate and plot conformer data (RMSD or energy).");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

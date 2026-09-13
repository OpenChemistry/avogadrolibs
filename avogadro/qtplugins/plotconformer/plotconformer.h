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
class QCheckBox;

namespace Avogadro {

namespace QtGui {
class ChartWidget;
}

namespace QtPlugins {

using DataSeries = std::vector<float>;

/**
 * @brief Generate and plot conformer data (RMSD, energy or scan coordinates)
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
  /**
   * Quantities that can drive either axis. The negative values name a
   * built-in series; zero and above index into the molecule's constraints, so
   * a scanned distance, angle or torsion can go on the x axis (a relaxed
   * torsion scan) or on the y axis (a bond length followed through a
   * reaction path).
   */
  enum Quantity
  {
    FrameQuantity = -1,
    RmsdQuantity = -2,
    EnergyQuantity = -3,
    ForcesQuantity = -4,
    VelocitiesQuantity = -5
  };

  // Show conformer @p frame, clamped to the available coordinate sets, and
  // tell the rest of the application about it.
  void setFrame(int frame);

  // Redraw the cached curve plus the marker for the current conformer. Cheap
  // enough to call on every arrow key, unlike updatePlot().
  void drawChart();

  // Fill both axis combos with the quantities the current molecule offers,
  // including one entry per usable constraint.
  void populateQuantityCombos();

  // The quantity selected on each axis, as a Quantity value or a constraint
  // index. Both fall back to Frame when the dialog does not exist yet.
  int xQuantity() const;
  int yQuantity() const;

  // True when @p quantity is a torsion coordinate, whose values wrap around.
  bool isTorsionQuantity(int quantity) const;

  // Evaluate @p quantity once per coordinate set, writing the axis label to
  // @p title. Returns false when the molecule holds no data for it.
  bool evaluateQuantity(int quantity, DataSeries& values, QString& title);

  // Series generators, one value per coordinate set. Each returns false when
  // the molecule cannot supply that quantity.
  bool generateFrameSeries(DataSeries& values);
  bool generateRmsdSeries(DataSeries& values);
  bool generateEnergySeries(DataSeries& values);
  bool generateForcesSeries(DataSeries& values);
  bool generateVelocitiesSeries(DataSeries& values);
  bool generateCoordinateSeries(int constraintIndex, DataSeries& values);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QAction* m_displayDialogAction;
  std::unique_ptr<QDialog> m_dialog;
  QtGui::ChartWidget* m_chartWidget;
  QComboBox* m_yAxisCombo;
  QComboBox* m_xAxisCombo;
  QComboBox* m_unitsCombo;
  QComboBox* m_targetUnitsCombo;
  QCheckBox* m_unwrapDihedralsCheck;
  QLabel* m_frameLabel;
  DataSeries m_xData;
  DataSeries m_yData;
  QString m_xTitle;
  QString m_yTitle;
  int m_currentFrame = 0;
};

inline QString PlotConformer::description() const
{
  return tr("Generate and plot conformer data (RMSD, energy or scan "
            "coordinates).");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

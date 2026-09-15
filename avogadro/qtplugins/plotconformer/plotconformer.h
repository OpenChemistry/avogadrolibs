/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTCONFORMER_H
#define AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/conformerquantity.h>

#include <QDialog>
#include <QComboBox>

#include <memory>
#include <optional>
#include <utility>
#include <vector>

class QLabel;
class QCheckBox;
class QDoubleSpinBox;
class QPushButton;

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

  // Turn the current selection into a plottable coordinate on the molecule.
  void addCoordinateFromSelection();

private:
  // True for the quantities that only mean anything once the frames are
  // spaced in time: the time axis itself, and everything that comes from the
  // velocities, which are differenced across the trajectory.
  static bool isDynamicsQuantity(const Core::ConformerQuantity& quantity);

  // Show conformer @p frame, clamped to the available coordinate sets, and
  // tell the rest of the application about it.
  void setFrame(int frame);

  // Redraw the cached curve plus the marker for the current conformer. Cheap
  // enough to call on every arrow key, unlike updatePlot().
  void drawChart();

  // Fill both axis combos from the quantities the current molecule offers.
  // The list itself comes from Core, so the conformer property table shows
  // the same one.
  void populateQuantityCombos();

  // Enable the selection button only for a selection that names a coordinate.
  void updateSelectionButton();

  // Index into m_quantities of the quantity selected on each axis, or -1 when
  // the dialog does not exist yet or the selection has gone stale.
  int xQuantity() const;
  int yQuantity() const;

  // The quantity at @p index, or nullptr when there is no such entry.
  const Core::ConformerQuantity* quantityAt(int index) const;

  // True when @p index names a torsion coordinate, whose values wrap around.
  bool isTorsionQuantity(int index) const;

  // One plotted series: a value per coordinate set, and the axis label for it.
  // A quantity that averages over the atoms also carries the spread of what it
  // averaged, which the chart draws as error bars when it is on the y axis.
  struct QuantitySeries
  {
    DataSeries values;
    DataSeries errors;
    QString title;
  };

  // Evaluate the quantity at @p index once per coordinate set. Empty when the
  // molecule holds no data for it.
  std::optional<QuantitySeries> evaluateQuantity(int index);

  // Make sure the molecule carries velocities for the quantities that need
  // them, estimating them from the trajectory and the time step below when it
  // does not. @return true when velocities are available afterwards.
  bool ensureVelocities();

  // Put the unit combos back in step with the application-wide setting, which
  // this dialog is only one of the places to change.
  void syncUnitCombos();

  // The interval between saved frames, in picoseconds, as the spin box has it.
  double timeStep() const;

  // Start the time step off at whatever the file recorded, where it recorded
  // anything, so the user is correcting a number rather than inventing one.
  void seedTimeStepFromMolecule();

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QAction* m_displayDialogAction;
  std::unique_ptr<QDialog> m_dialog;
  QtGui::ChartWidget* m_chartWidget;
  QComboBox* m_yAxisCombo;
  QComboBox* m_xAxisCombo;
  QComboBox* m_unitsCombo;
  QDoubleSpinBox* m_timeStepSpin;
  QComboBox* m_targetUnitsCombo;
  QCheckBox* m_unwrapDihedralsCheck;
  QLabel* m_timeStepLabel;
  QPushButton* m_addSelectionButton;
  QLabel* m_frameLabel;
  // Everything measurable on the molecule, in the order the combos list it.
  std::vector<Core::ConformerQuantity> m_quantities;
  DataSeries m_xData;
  DataSeries m_yData;
  // Half-height of the error bar on each y point, empty when the quantity has
  // no spread to show.
  DataSeries m_yErrors;
  QString m_xTitle;
  QString m_yTitle;
  // Axis limits belong to the data, so they are worked out once when it is
  // rebuilt rather than on every redraw -- drawChart() runs on each arrow key.
  std::pair<float, float> m_xLimits{ 0.0f, 1.0f };
  std::pair<float, float> m_yLimits{ 0.0f, 1.0f };
  int m_currentFrame = 0;
  // Set when the atoms have moved under velocities differenced from where
  // they used to be. Core notices a trajectory that changed length or a frame
  // interval that changed value on its own; this is the case it cannot see.
  bool m_staleVelocities = true;
  // Whether the time step has been seeded from this molecule yet. Re-seeding
  // would throw away a value the user typed.
  bool m_timeStepSeeded = false;
};

inline QString PlotConformer::description() const
{
  return tr("Generate and plot conformer data (RMSD, energy or scan "
            "coordinates).");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

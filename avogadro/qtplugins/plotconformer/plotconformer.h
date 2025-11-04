/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTCONFORMER_H
#define AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

#include <avogadro/qtgui/extensionplugin.h>

#include <memory>

namespace Avogadro {

namespace QtGui {
class ChartDialog;
}

namespace QtPlugins {

// First item in the pair is the frame number.
// Second is the RMSD value or energy
typedef std::vector<std::pair<double, double>> PlotData;

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

private:
  // Generate RMSD data from a coordinate set
  // Writes the results to @p results, which is a vector of pairs of doubles
  // (see definition above).
  void generateRmsdCurve(PlotData& results);

  // Generate a relative energy data from a coordinate set
  // Writes the results to @p results, which is a vector of pairs of doubles
  // (see definition above).
  void generateEnergyCurve(PlotData& results);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QAction* m_displayDialogAction;
  QScopedPointer<QtGui::ChartDialog> m_chartDialog;
};

inline QString PlotConformer::description() const
{
  return tr("Generate and plot conformer data (RMSD or energy).");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTCONFORMER_H

/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTRMSD_H
#define AVOGADRO_QTPLUGINS_PLOTRMSD_H

#include <avogadro/qtgui/extensionplugin.h>

#include <memory>

// Forward declarations
class QByteArray;
class QStringList;

namespace VTK {
class VtkPlot;
}

namespace Avogadro {
namespace QtPlugins {

// First item in the pair is the frame number. Second is the RMSD value.
typedef std::vector<std::pair<double, double>> RmsdData;

/**
 * @brief Generate and plot an RMSD curve.
 */
class PlotRmsd : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit PlotRmsd(QObject* parent_ = nullptr);
  ~PlotRmsd();

  QString name() const { return tr("PlotRmsd"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);

  void moleculeChanged(unsigned int changes);

private slots:
  void updateActions();

  void displayDialog();

private:
  // Generate RMSD data from a coordinate set
  // Writes the results to @p results, which is a vector of pairs of doubles
  // (see definition above).
  void generateRmsdPattern(RmsdData& results);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  std::unique_ptr<QAction> m_displayDialogAction;
  QScopedPointer<VTK::VtkPlot> m_plot;
};

inline QString PlotRmsd::description() const
{
  return tr("Generate and plot an RMSD curve.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTRMSD_H

/*******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTPDF_H
#define AVOGADRO_QTPLUGINS_PLOTPDF_H

#include <avogadro/qtgui/extensionplugin.h>

// Forward declarations
class QByteArray;
class QStringList;

namespace VTK {
class VtkPlot;
}

namespace Avogadro {
namespace QtPlugins {

class PdfOptionsDialog;

// First item in the pair is radius. Second is the pdf value.
typedef std::vector<std::pair<double, double>> PdfData;

/**
 * @brief Generate and plot a PDF curve
 */
class PlotPdf : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit PlotPdf(QObject* parent_ = nullptr);
  ~PlotPdf();

  QString name() const { return tr("PlotPdf"); }
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
  // Generate Pdf curve from a crystal
  // Writes the results to @p results, which is a vector of pairs of doubles
  // (see definition above).
  // err will be set to an error string if the function fails.
  // radius is in Angstroms.
  static bool generatePdfPattern(QtGui::Molecule& mol, PdfData& results,
                                 QString& err, double maxRadius = 10.0,
                                 double step = 0.1);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  QScopedPointer<PdfOptionsDialog> m_pdfOptionsDialog;
  QScopedPointer<QAction> m_displayDialogAction;
  QScopedPointer<VTK::VtkPlot> m_plot;
};

inline QString PlotPdf::description() const
{
  return tr("Generate and plot a Pair Distribution Function curve.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTPDF_H

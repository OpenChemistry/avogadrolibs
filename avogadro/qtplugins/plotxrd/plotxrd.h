/*******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2018 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PLOTXRD_H
#define AVOGADRO_QTPLUGINS_PLOTXRD_H

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

class XrdOptionsDialog;

// First item in the pair is 2*theta. Second is the intensity.
typedef std::vector<std::pair<double, double>> XrdData;

/**
 * @brief Generate and plot a theoretical XRD pattern using ObjCryst++
 */
class PlotXrd : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit PlotXrd(QObject* parent_ = nullptr);
  ~PlotXrd();

  QString name() const { return tr("PlotXrd"); }
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
  // Generate an Xrd pattern from a crystal
  // Writes the results to @p results, which is a vector of pairs of doubles
  // (see definition above).
  // err will be set to an error string if the function fails.
  // wavelength is an Angstroms.
  // peakwidth is in degrees.
  // numpoints is an unsigned integer.
  // max2theta is in degrees.
  static bool generateXrdPattern(const QtGui::Molecule& mol, XrdData& results,
                                 QString& err, double wavelength = 1.505600,
                                 double peakwidth = 0.529580,
                                 size_t numpoints = 1000,
                                 double max2theta = 162.0);

  // Use QProcess to execute genXrdPattern
  // If the GENXRDPATTERN_EXECUTABLE environment variable is set, that will be
  // used for the executable. Otherwise, it will search for the executable in
  // some common places and use it if it can be found.
  static bool executeGenXrdPattern(const QStringList& args,
                                   const QByteArray& input, QByteArray& output,
                                   QString& err);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  std::unique_ptr<XrdOptionsDialog> m_xrdOptionsDialog;
  std::unique_ptr<QAction> m_displayDialogAction;
  QScopedPointer<VTK::VtkPlot> m_plot;
};

inline QString PlotXrd::description() const
{
  return tr("Generate and plot a theoretical XRD pattern using ObjCryst++.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_PLOTXRD_H

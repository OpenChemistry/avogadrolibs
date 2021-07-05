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

#ifndef AVOGADRO_QTPLUGINS_YAEHMOP_H
#define AVOGADRO_QTPLUGINS_YAEHMOP_H

#include <avogadro/qtgui/extensionplugin.h>

#include <avogadro/core/vector.h>

#include <memory>

#include "yaehmopsettings.h"

// Forward declarations
class QByteArray;
class QStringList;

namespace VTK {
class VtkPlot;
}

namespace Avogadro {
namespace QtPlugins {

class BandDialog;

/**
 * @brief Perform extended Hückel calculations with yaehmop.
 */
class Yaehmop : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Yaehmop(QObject* parent_ = nullptr);
  ~Yaehmop();

  QString name() const { return tr("Yaehmop"); }
  QString description() const;
  QList<QAction*> actions() const;
  QStringList menuPath(QAction*) const;

public slots:
  void setMolecule(QtGui::Molecule* mol);

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
  static bool executeYaehmop(const QByteArray& input, QByteArray& output,
                             QString& err);

  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  YaehmopSettings m_yaehmopSettings;

  std::unique_ptr<BandDialog> m_bandDialog;
  std::unique_ptr<QAction> m_displayBandDialogAction;
  std::unique_ptr<VTK::VtkPlot> m_bandPlot;
};

inline QString Yaehmop::description() const
{
  return tr("Perform extended Hückel calculations with yaehmop.");
}

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_YAEHMOPEXTENSION_H

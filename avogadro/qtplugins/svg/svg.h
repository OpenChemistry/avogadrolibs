/******************************************************************************

   This source file is part of the Avogadro project.

   Copyright 2020 Kitware, Inc.

   This source code is released under the New BSD License, (the "License").

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SVG_H
#define AVOGADRO_QTPLUGINS_SVG_H

#include <Eigen/Geometry>
#include <QPainter>
#include <avogadro/core/vector.h>
#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/molecule.h>
#include <map>
#include <vector>

namespace Avogadro {
namespace QtPlugins {
typedef Avogadro::Core::Array<Avogadro::Core::Bond> NeighborListType;

class SVG : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit SVG(QObject* parent_ = 0);
  ~SVG() override;
  QString name() const override { return tr("SVG"); }

  QString description() const override
  {
    return tr("Render the scene in a SVG file.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;
  void setScene(Rendering::Scene* scene) override;
  void setCamera(Rendering::Camera* camera) override;

private slots:
  void render();

private:
  struct Mol
  {
    Eigen::Vector3f pos_model, pos_view, pos_image;
    unsigned int r;
    unsigned int id;

    Mol(Vector3f m, Vector3f v, unsigned int i, unsigned int bonds)
      : pos_model(m), pos_view(v), id(i)
    {
      r = (bonds <= 0 ? 1 : bonds);
    }
  };
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
  int m_width, m_height;
  Eigen::Vector3f m_min, m_max;
  std::vector<Mol> m_mols;
  std::vector<Eigen::Vector4f> m_frustrum;
  std::map<unsigned int, unsigned int> m_idToindex;

  static const float RADIUS, PEN_WIDTH_MOL, PEN_WIDTH_BOND, OFF_SET_PARALEL,
    IMAGE_PADDING;

  void paintSVG(QPainter& painter);
  void paintMol(QPainter& painter, const Mol& mol);
  void paintBonds(QPainter& painter, const Mol& mol, unsigned int i,
                  const NeighborListType& bonds);

  bool defaultChecks();
  void getPositions();
  void calculateCamera();
  bool frustrumCulling(const Mol& mol);
  Eigen::Vector3f posToImage(const Vector3f& mol, float r);
};
} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SVG_H

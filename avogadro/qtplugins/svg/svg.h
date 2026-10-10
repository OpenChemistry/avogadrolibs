/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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
  explicit SVG(QObject* parent_ = nullptr);
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
  struct SVGAtom
  {
    Eigen::Vector3f pos_model, pos_view, pos_image;
    unsigned int radius;
    unsigned int id;

    SVGAtom(Vector3f m, Vector3f v, unsigned int i, unsigned int bonds)
      : pos_model(m), pos_view(v), id(i)
    {
      radius = (bonds <= 0 ? 1 : bonds);
    }
  };
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  Rendering::Camera* m_camera;

  QAction* m_action;
  int m_width, m_height;
  Eigen::Vector3f m_min, m_max;
  std::vector<SVGAtom> m_atoms;
  std::vector<Eigen::Vector4f> m_frustrum;
  std::map<unsigned int, unsigned int> m_idToindex;

  static const float DEFAULT_RADIUS, DEFAULT_PEN_WIDTH_MOL,
    DEFAULT_PEN_WIDTH_BOND, DEFAULT_OFF_SET_PARALEL, DEFAULT_IMAGE_PADDING;
  static const Vector3ub DEFAULT_BOND_COLOR;

  float m_radius, m_penWidthMol, m_penWidthBond, m_offSetParalel,
    m_ImagePadding;
  Vector3ub m_BondColor;
  void paintSVG(QPainter& painter);
  void paintCore(QPainter& painter, const SVGAtom& atom);
  void paintBonds(QPainter& painter, const SVGAtom& atom, unsigned int i,
                  const NeighborListType& bonds);

  bool defaultChecks();
  void setOptions();
  void getPositions();
  void calculateCamera();
  bool frustrumCulling(const SVGAtom& atom);
  Eigen::Vector3f posToSVGImage(const SVGAtom& atom);
};
} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SVG_H

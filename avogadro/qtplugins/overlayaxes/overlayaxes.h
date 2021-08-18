/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OVERLAYAXES_H
#define AVOGADRO_QTPLUGINS_OVERLAYAXES_H

#include <avogadro/qtgui/extensionplugin.h>
#include <avogadro/qtgui/molecule.h>
#include <avogadro/qtgui/rwmolecule.h>

#include <avogadro/rendering/groupnode.h>

#include <map>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render reference axes in the corner of the display.
 */
class OverlayAxes : public Avogadro::QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit OverlayAxes(QObject* parent = nullptr);
  ~OverlayAxes() override;

  QString name() const override { return tr("Reference Axes Overlay"); }
  QString description() const override
  {
    return tr("Render reference axes in the corner of the display.");
  }

  QList<QAction*> actions() const override;
  QStringList menuPath(QAction*) const override;

public slots:
  void setMolecule(QtGui::Molecule* molecule) override;
  void setScene(Rendering::Scene* scene) override;
  void setActiveWidget(QWidget* widget) override;

signals:
  void updateRequested();

private slots:
  void processAxes();

private:
  void process(const Core::Molecule& molecule, Rendering::GroupNode& node);

  bool m_enabled;
  bool m_initialized;

  class RenderImpl;
  RenderImpl* const m_render;
  std::map<QWidget*, Rendering::GroupNode*> m_widgetToNode;
  QtGui::Molecule* m_molecule;
  Rendering::Scene* m_scene;
  QWidget* m_glWidget;
  QAction* m_axesAction;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OVERLAYAXES_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_WIREFRAME_H
#define AVOGADRO_QTPLUGINS_WIREFRAME_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render a molecule in the wireframe style.
 */
class Wireframe : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Wireframe(QObject* parent = nullptr);
  ~Wireframe() override;

  void process(const Core::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Wireframe"); }

  QString description() const override
  {
    return tr("Render the molecule as a wireframe.");
  }

  bool isEnabled() const override;

  void setEnabled(bool enable) override;

  QWidget* setupWidget() override;

private slots:
  void multiBonds(bool show);
  void showHydrogens(bool show);
  void setWidth(double width);

private:
  bool m_enabled;

  Rendering::GroupNode* m_group;

  QWidget* m_setupWidget;
  bool m_multiBonds;
  bool m_showHydrogens;
  float m_lineWidth;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_WIREFRAME_H

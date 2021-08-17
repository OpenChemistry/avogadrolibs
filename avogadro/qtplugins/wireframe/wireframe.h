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

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr(m_name.c_str()); }

  QString description() const override
  {
    return tr("Render the molecule as a wireframe.");
  }

  QWidget* setupWidget() override;

public slots:
  void multiBonds(bool show);
  void showHydrogens(bool show);
  void setWidth(double width);

private:
  Rendering::GroupNode* m_group;
  std::string m_name = "Wireframe";
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_WIREFRAME_H

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
class Force : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Force(QObject* parent = nullptr);
  ~Force() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Force"); }

  QString description() const override
  {
    return tr(
      "Render the force field visualizations for the atoms of the molecule.");
  }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

private:
  std::string m_name = "Force";
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_WIREFRAME_H

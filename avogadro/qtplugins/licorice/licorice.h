/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LICORICE_H
#define AVOGADRO_QTPLUGINS_LICORICE_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render a molecule in the licorice style.
 * @author Marcus D. Hanwell
 */
class Licorice : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Licorice(QObject* parent = nullptr);
  ~Licorice() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr(m_name.c_str()); }

  QString description() const override
  {
    return tr("Render atoms as licorice / sticks.");
  }

private:
  std::string m_name = "Licorice";
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LICORICE_H

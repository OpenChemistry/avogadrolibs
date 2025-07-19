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

  QString name() const override
  {
    return tr("Licorice", "stick / licorice rendering");
  }

  QString description() const override
  {
    return tr("Render atoms as licorice / sticks.");
  }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return true; }

public slots:
  void setOpacity(int opacity);

private:
  std::string m_name = "Licorice";
  QWidget* m_setupWidget = nullptr;
  float m_opacity = 1.0;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LICORICE_H

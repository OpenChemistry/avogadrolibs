/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CLOSECONTACTS_H
#define AVOGADRO_QTPLUGINS_CLOSECONTACTS_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Detect and render close contacts between atoms.
 * @author Aritz Erkiaga
 */
class CloseContacts : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit CloseContacts(QObject* parent = nullptr);
  ~CloseContacts() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Close Contacts", "rendering of non-covalent close contacts"); }

  QString description() const override
  {
    return tr("Render close contacts between atoms.");
  }
  
  QWidget* setupWidget() override;

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

public slots:
  void setMaximumDistance(float maximumDistance, Index index);
  void setLineWidth(float width, Index index);

private:
  std::string m_name = "Close Contacts";
  
  const std::array<QString, 3> INTERACTION_NAMES = {
	tr("Contact"), tr("Salt Bridge"), tr("Repulsive")
  };

  std::array<double, 3> m_maximumDistances;
  std::array<Vector3ub, 3> m_lineColors;
  std::array<float, 3> m_lineWidths;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CLOSECONTACTS_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CLOSECONTACTS_H
#define AVOGADRO_QTPLUGINS_CLOSECONTACTS_H

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

  QString name() const override { return tr(m_name.c_str()); }

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
  void setMaximumDistance(double maximumDistance);

private:
  std::string m_name = "Close Contacts";
  
  double m_maximumDistance;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CLOSECONTACTS_H

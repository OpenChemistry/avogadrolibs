/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_DIPOLE_H
#define AVOGADRO_QTPLUGINS_DIPOLE_H

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render a molecule dipole moment arrow
 */
class Dipole : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Dipole(QObject* parent = nullptr);
  ~Dipole() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("Dipole Moment"); }

  QString description() const override
  {
    return tr("Render the dipole moment of the molecule.");
  }

  DefaultBehavior defaultBehavior() const override
  {
    return DefaultBehavior::False;
  }

  QWidget* setupWidget() override;
  bool hasSetupWidget() const override { return false; }

public slots:
  void updateDipole();
  void updateFinished();

private:
  std::string m_name = "Dipole Moment";
  std::string m_type = "MMFF94";
  std::vector<std::string> m_types;
  Vector3 m_dipoleVector;
  Vector3 m_customDipoleVector;
  bool m_customDipole = false; // Custom dipole moment set
  bool m_updateNeeded = true;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_FORCE_H

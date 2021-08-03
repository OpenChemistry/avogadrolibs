/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_LABEL_H
#define AVOGADRO_QTPLUGINS_LABEL_H

#include <avogadro/qtgui/sceneplugin.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief Render labels to each atom.
 */
class Label : public QtGui::ScenePlugin
{
  Q_OBJECT

public:
  explicit Label(QObject* parent = nullptr);
  ~Label() override;

  QString name() const override { return tr("Labels"); }
  QString description() const override
  {
    return tr("Display labels on ball and stick style.");
  }

  bool isEnabled() const override;

  void setEnabled(bool enable) override;

  QWidget* setupWidget() override;
  void process(const Core::Molecule& molecule, Rendering::GroupNode& node);

private slots:
  void atomLabel(bool show);
  void residueLabel(bool show);

private:
  void processAtom(const Core::Molecule& molecule, Rendering::GroupNode& node);
  void processResidue(const Core::Molecule& molecule,
                      Rendering::GroupNode& node);

  bool m_enabled;

  Rendering::GroupNode* m_group;

  QWidget* m_setupWidget;

  bool m_atomLabel;
  bool m_residueLabel;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_LABEL_H

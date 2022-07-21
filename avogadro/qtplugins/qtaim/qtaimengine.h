/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef QTAIMENGINE_H
#define QTAIMENGINE_H

#include <avogadro/qtgui/sceneplugin.h>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtPlugins {

class QTAIMEngine : public QtGui::ScenePlugin
{
  Q_OBJECT
public:
  explicit QTAIMEngine(QObject* parent = nullptr);
  virtual ~QTAIMEngine() override;

  void process(const QtGui::Molecule& molecule,
               Rendering::GroupNode& node) override;

  QString name() const override { return tr("QTAIM"); }

  QString description() const override
  {
    return tr("Renders primitives using QTAIM properties");
  }

  bool isEnabled() const override { return m_enabled; }

  void setEnabled(bool enable) override { m_enabled = enable; }

private:
  bool m_enabled;
};

} // end namespace QtPlugins
} // end namespace Avogadro

#endif

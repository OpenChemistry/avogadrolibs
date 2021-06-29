/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BONDING_H
#define AVOGADRO_QTPLUGINS_BONDING_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtWidgets/QDialog>

namespace Ui {
class BondingDialog;
}

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Bonding class performs bonding operations on demand.
 */
class Bonding : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Bonding(QObject* parent_ = nullptr);
  ~Bonding() override;

  QString name() const override { return tr("Bonding"); }

  QString description() const override
  {
    return tr("Perform bonding operations.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void bond();
  void clearBonds();
  void configure();
  void setValues();

private:
  QtGui::Molecule* m_molecule;

  double m_tolerance;
  double m_minDistance;

  QAction* m_action;
  QAction* m_clearAction;
  QAction* m_configAction;

  QDialog* m_dialog;
  Ui::BondingDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_BONDING_H

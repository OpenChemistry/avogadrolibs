/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_BONDING_H
#define AVOGADRO_QTPLUGINS_BONDING_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

#include <QtWidgets/QDialog>

namespace Ui {
class BondingDialog;
}

namespace Avogadro::QtPlugins {

/**
 * @brief The Bonding class performs bonding operations on demand.
 */
class Bonding : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Bonding(QObject* parent_ = nullptr);
  ~Bonding() override = default;

  QString name() const override { return tr("Bonding"); }

  QString description() const override
  {
    return tr("Perform bonding operations.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

  bool handleCommand(const QString& command,
                     const QVariantMap& options) override;

  void registerCommands() override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void bond();
  void createBond();
  void bondOrders();
  void clearBonds();
  void configure();
  void setValues();

private:
  QtGui::Molecule* m_molecule;

  double m_tolerance;
  double m_minDistance;

  QAction* m_action;
  QAction* m_orderAction;
  QAction* m_clearAction;
  QAction* m_configAction;
  QAction* m_createBondsAction;

  QDialog* m_dialog;
  Ui::BondingDialog* m_ui;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_BONDING_H

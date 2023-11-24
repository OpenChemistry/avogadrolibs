/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H
#define AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H

#include <memory>

#include <QDialog>

#include "yaehmopsettings.h"

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class BandDialog;
}

/**
 * @brief Dialog to perform a band structure calculation with yaehmop.
 */
class BandDialog : public QDialog
{
  Q_OBJECT

public:
  explicit BandDialog(QWidget* parent, YaehmopSettings& yaehmopSettings);
  ~BandDialog();

public slots:
  int exec() override;

protected slots:
  void accept() override;

private:
  std::unique_ptr<Ui::BandDialog> m_ui;
  YaehmopSettings& m_yaehmopSettings;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_YAEHMOPBANDDIALOG_H

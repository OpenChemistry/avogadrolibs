/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CONDADIALOG_H
#define AVOGADRO_QTPLUGINS_CONDADIALOG_H

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class CondaDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class CondaDialog : public QDialog
{
  Q_OBJECT

public:
  explicit CondaDialog(QWidget* parent = nullptr);
  ~CondaDialog() override;

  QString environmentName() const;

private:
  Ui::CondaDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_CONDADIALOG_H

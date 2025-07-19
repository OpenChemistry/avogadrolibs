/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H
#define AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H

#include <avogadro/core/avogadrocore.h>

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace QtGui {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class SupercellDialog;
}

/**
 * @brief The SupercellDialog class provides a dialog for
 * building a supercell from a crystal.
 */

class SupercellDialog : public QDialog
{
  Q_OBJECT
public:
  SupercellDialog(QWidget* p = nullptr);
  ~SupercellDialog() override;

  bool buildSupercell(Avogadro::QtGui::Molecule& mol);

  void displayInvalidFormatMessage();

private:
  AVO_DISABLE_COPY(SupercellDialog)

  Ui::SupercellDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_SUPERCELLDIALOG_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H
#define AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H

#include <avogadro/core/avogadrocore.h>

#include <QtWidgets/QDialog>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace QtPlugins {

namespace Ui {
class ImportCrystalDialog;
}

/**
 * @brief The ImportCrystalDialog class provides a dialog for importing
 * a crystal from the clipboard.
 */

class ImportCrystalDialog : public QDialog
{
  Q_OBJECT
public:
  ImportCrystalDialog(QWidget* p = nullptr);
  ~ImportCrystalDialog() override;

  // Avogadro::Core::Molecule is required for the format function
  bool importCrystalClipboard(Avogadro::Core::Molecule& mol);

  void displayInvalidFormatMessage();

private:
  AVO_DISABLE_COPY(ImportCrystalDialog)

  Ui::ImportCrystalDialog* m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_IMPORTCRYSTALDIALOG_H

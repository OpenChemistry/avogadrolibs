/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CUSTOMELEMENTDIALOG_H
#define AVOGADRO_QTGUI_CUSTOMELEMENTDIALOG_H

#include "avogadroqtguiexport.h"
#include <QtWidgets/QDialog>

#include <avogadro/core/avogadrocore.h>

namespace Avogadro {
namespace QtGui {
class Molecule;

namespace Ui {
class CustomElementDialog;
}

/**
 * @class CustomElementDialog customelementdialog.h
 * <avogadro/qtgui/customelementdialog.h>
 * @brief Dialog window for mapping custom elements into elemental types.
 */
class AVOGADROQTGUI_EXPORT CustomElementDialog : public QDialog
{
  Q_OBJECT
public:
  explicit CustomElementDialog(Molecule& mol, QWidget* parent = nullptr);
  ~CustomElementDialog() override;

  /**
   * Static entry point for using this dialog. @a parent is the parent of the
   * dialog, @a mol is the molecule to operate on.
   */
  static void resolve(QWidget* parent, Molecule& mol);

public slots:
  /** Apply the changes to the molecule. */
  void apply();

private:
  Ui::CustomElementDialog* m_ui;
  Molecule& m_molecule;
  QStringList m_elements;

  void prepareElements();
  void prepareForm();
  void addRow(unsigned char customElementId, const QString& name);
};

} // namespace QtGui
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_CUSTOMELEMENTDIALOG_H

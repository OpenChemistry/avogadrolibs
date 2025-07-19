/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_INSERTFRAGMENTDIALOG_H
#define AVOGADRO_QTGUI_INSERTFRAGMENTDIALOG_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QDialog>

namespace Avogadro {
namespace QtGui {

namespace Ui {
class InsertFragmentDialog;
}

/**
 * @brief Dialog to prompt a format and descriptor string.
 */
class AVOGADROQTGUI_EXPORT InsertFragmentDialog : public QDialog
{
  Q_OBJECT

public:
  explicit InsertFragmentDialog(QWidget* parent = nullptr,
                                QString directory = "molecules");
  ~InsertFragmentDialog() override;

  QString fileName();

public Q_SLOTS:
  void refresh();

  void filterTextChanged(const QString&);

  void activated();

  void currentChanged(const QModelIndex& selected,
                      const QModelIndex& deselected);

Q_SIGNALS:
  void performInsert(const QString& fileName, bool crystal);

private:
  Ui::InsertFragmentDialog* m_ui;

  class Private;
  Private* m_implementation;
};

} // namespace QtGui
} // namespace Avogadro
#endif // AVOGADRO_QTGUI_InsertFragmentDIALOG_H

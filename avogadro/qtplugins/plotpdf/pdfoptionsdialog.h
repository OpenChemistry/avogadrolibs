/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H
#define AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H

#include <QDialog>

namespace Avogadro {
namespace QtPlugins {

namespace Ui {
class PdfOptionsDialog;
}

/**
 * @brief Dialog to set options for PDF curve plotting.
 */
class PdfOptionsDialog : public QDialog
{
  Q_OBJECT

public:
  explicit PdfOptionsDialog(QWidget* parent = nullptr);
  ~PdfOptionsDialog();

  double maxRadius() const;
  double step() const;

protected slots:
  void accept();

private:
  QScopedPointer<Ui::PdfOptionsDialog> m_ui;
};

} // namespace QtPlugins
} // namespace Avogadro
#endif // AVOGADRO_QTPLUGINS_PDFOPTIONSDIALOG_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef CONFORMERSEARCHDIALOG_H
#define CONFORMERSEARCHDIALOG_H

#include <QDialog>

#include "ui_conformersearchdialog.h"

namespace Avogadro {
class ConformerSearchDialog : public QDialog
{
  Q_OBJECT

public:
  //! Constructor
  explicit ConformerSearchDialog(QWidget* parent = 0, Qt::WindowFlags f = 0);
  //! Desconstructor
  ~ConformerSearchDialog();

  int method();
  int numConformers();

  QStringList options() const;

public slots:
  void accept();
  void reject();
  void systematicToggled(bool checked);
  void randomToggled(bool checked);
  void weightedToggled(bool checked);
  void geneticToggled(bool checked);

  void buttonClicked(QAbstractButton* button);

signals:
  void accepted();

private:
  Ui::ConformerSearchDialog ui;

  int m_method;
  int m_numConformers;
};
} // namespace Avogadro

#endif

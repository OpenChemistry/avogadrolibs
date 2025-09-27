/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CHARTDIALOG_H
#define AVOGADRO_QTGUI_CHARTDIALOG_H

#include "avogadroqtguiexport.h"

#include <QDialog>

namespace Avogadro::QtGui {

class ChartWidget;

class AVOGADROQTGUI_EXPORT ChartDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ChartDialog(QWidget* p = nullptr);
  ~ChartDialog() override;

  ChartWidget* chartWidget();

  QSize sizeHint() const override;
  QSize minimumSizeHint() const override;

private:
  ChartWidget* m_chartWidget;
};

} // namespace Avogadro::QtGui

#endif // AVOGADRO_CHARTDIALOG_H

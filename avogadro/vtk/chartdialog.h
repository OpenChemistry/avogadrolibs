/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#pragma once

#include "avogadrovtkexport.h"

#include <QDialog>

namespace Avogadro::VTK {

class ChartWidget;

class AVOGADROVTK_EXPORT ChartDialog : public QDialog
{
  Q_OBJECT

public:
  explicit ChartDialog(QWidget* p = nullptr);
  ~ChartDialog() override;

  ChartWidget* chartWidget();

private:
  ChartWidget* m_chartWidget;
};

} // namespace Avogadro::VTK

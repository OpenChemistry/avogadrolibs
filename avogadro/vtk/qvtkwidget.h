/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#pragma once

#include "avogadrovtkexport.h"

#include <avogadro/rendering/glrenderer.h>

#include <QVTKOpenGLStereoWidget.h>

namespace Avogadro::VTK {

class AVOGADROVTK_EXPORT QVTKWidget : public QVTKOpenGLStereoWidget
{
  Q_OBJECT

public:
  explicit QVTKWidget(QWidget* parent = nullptr,
                      Qt::WindowFlags f = Qt::WindowFlags());
  ~QVTKWidget() override;
};
} // namespace Avogadro::VTK

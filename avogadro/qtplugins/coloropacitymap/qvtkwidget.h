/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_QTPLUGINS_QVTKGLWidget_H
#define AVOGADRO_QTPLUGINS_QVTKGLWidget_H

#include <QVTKOpenGLWidget.h>

namespace Avogadro {

class QVTKGLWidget : public QVTKOpenGLWidget
{
  Q_OBJECT

public:
  QVTKGLWidget(QWidget* parent = nullptr,
               Qt::WindowFlags f = Qt::WindowFlags());
  ~QVTKGLWidget() override;

  void setEnableHiDPI(bool enable) override;
};
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_QVTKGLWidget_H

/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef AVOGADRO_QTPLUGINS_HISTOGRAMWIDGET_H
#define AVOGADRO_QTPLUGINS_HISTOGRAMWIDGET_H

#include <QWidget>

#include <vtkNew.h>
#include <vtkWeakPointer.h>

class vtkChartHistogramColorOpacityEditor;
class vtkContextView;
class vtkEventQtSlotConnect;
class vtkPiecewiseFunction;
class vtkObject;
class vtkTable;

class QToolButton;

class vtkColorTransferFunction;

namespace Avogadro {

class QVTKGLWidget;

class HistogramWidget : public QWidget
{
  Q_OBJECT

public:
  explicit HistogramWidget(QWidget* parent_ = nullptr);
  ~HistogramWidget() override;

  void setLUT(vtkColorTransferFunction* lut);
  vtkColorTransferFunction* LUT();

  void setOpacityFunction(vtkPiecewiseFunction* opacity);
  vtkPiecewiseFunction* opacityFunction();

  void setInputData(vtkTable* table, const char* x, const char* y);

signals:
  void colorMapUpdated();
  void opacityChanged();

public slots:
  void onScalarOpacityFunctionChanged();
  void onCurrentPointEditEvent();
  void histogramClicked(vtkObject*);

  void updateUI();

protected:
  void showEvent(QShowEvent* event) override;

private:
  void renderViews();
  vtkNew<vtkChartHistogramColorOpacityEditor> m_histogramColorOpacityEditor;
  vtkNew<vtkContextView> m_histogramView;
  vtkNew<vtkEventQtSlotConnect> m_eventLink;

  vtkWeakPointer<vtkColorTransferFunction> m_LUT;
  vtkWeakPointer<vtkPiecewiseFunction> m_opacityFunction;
  vtkWeakPointer<vtkTable> m_inputData;

  QVTKGLWidget* m_qvtk;
};
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_HISTOGRAMWIDGET_H

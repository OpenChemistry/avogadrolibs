/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "histogramwidget.h"

#include "qvtkwidget.h"

#include <avogadro/qtopengl/activeobjects.h>
#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/vtk/vtkglwidget.h>

#include "vtkChartHistogramColorOpacityEditor.h"

#include <vtkContextScene.h>
#include <vtkContextView.h>
#include <vtkControlPointsItem.h>
#include <vtkDataArray.h>
#include <vtkEventQtSlotConnect.h>
#include <vtkPiecewiseFunction.h>
#include <vtkRenderWindow.h>
#include <vtkTable.h>
#include <vtkVector.h>

#include <vtkColorTransferFunction.h>

#include <QCheckBox>
#include <QColorDialog>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QToolButton>
#include <QVBoxLayout>

#include <QDebug>

namespace Avogadro {

using QtOpenGL::ActiveObjects;

HistogramWidget::HistogramWidget(QWidget* parent)
  : QWidget(parent), m_qvtk(new QVTKGLWidget(this))
{
  // Set up our little chart.
  m_histogramView->SetRenderWindow(m_qvtk->GetRenderWindow());
  m_histogramView->SetInteractor(m_qvtk->GetInteractor());
  m_histogramView->GetScene()->AddItem(m_histogramColorOpacityEditor);

  // Connect events from the histogram color/opacity editor.
  m_eventLink->Connect(m_histogramColorOpacityEditor,
                       vtkCommand::CursorChangedEvent, this,
                       SLOT(histogramClicked(vtkObject*)));
  m_eventLink->Connect(m_histogramColorOpacityEditor, vtkCommand::EndEvent,
                       this, SLOT(onScalarOpacityFunctionChanged()));
  m_eventLink->Connect(m_histogramColorOpacityEditor,
                       vtkControlPointsItem::CurrentPointEditEvent, this,
                       SLOT(onCurrentPointEditEvent()));

  auto hLayout = new QHBoxLayout(this);
  hLayout->addWidget(m_qvtk);
  setLayout(hLayout);
}

HistogramWidget::~HistogramWidget() = default;

void HistogramWidget::setLUT(vtkColorTransferFunction* lut)
{
  if (m_LUT != lut) {
    m_LUT = lut;
    m_histogramColorOpacityEditor->SetColorTransferFunction(lut);

    emit colorMapUpdated();
  }
}

void HistogramWidget::setOpacityFunction(vtkPiecewiseFunction* opacity)
{
  if (m_opacityFunction) {
    m_eventLink->Disconnect(m_opacityFunction, vtkCommand::ModifiedEvent, this,
                            SLOT(onScalarOpacityFunctionChanged()));
  }
  m_opacityFunction = opacity;
  m_histogramColorOpacityEditor->SetOpacityFunction(opacity);
  m_eventLink->Connect(m_opacityFunction, vtkCommand::ModifiedEvent, this,
                       SLOT(onScalarOpacityFunctionChanged()));
}

vtkColorTransferFunction* HistogramWidget::LUT()
{
  return m_LUT;
}

vtkPiecewiseFunction* HistogramWidget::opacityFunction()
{
  return m_opacityFunction;
}

void HistogramWidget::setInputData(vtkTable* table, const char* x,
                                   const char* y)
{
  m_inputData = table;
  m_histogramColorOpacityEditor->SetHistogramInputData(table, x, y);
  m_histogramColorOpacityEditor->SetOpacityFunction(m_opacityFunction);
  if (m_LUT && table) {
    m_histogramColorOpacityEditor->SetScalarVisibility(true);
    m_histogramColorOpacityEditor->SetColorTransferFunction(m_LUT);
    m_histogramColorOpacityEditor->SelectColorArray("image_extents");
  }
  m_histogramView->Render();
}

void HistogramWidget::onScalarOpacityFunctionChanged()
{
  // Update the histogram
  m_histogramView->GetRenderWindow()->Render();

  emit opacityChanged();
}

void HistogramWidget::onCurrentPointEditEvent()
{
  double rgb[3];
  if (m_histogramColorOpacityEditor->GetCurrentControlPointColor(rgb)) {
    QColor color =
      QColorDialog::getColor(QColor::fromRgbF(rgb[0], rgb[1], rgb[2]), this,
                             "Select Color for Control Point");
    if (color.isValid()) {
      rgb[0] = color.redF();
      rgb[1] = color.greenF();
      rgb[2] = color.blueF();
      m_histogramColorOpacityEditor->SetCurrentControlPointColor(rgb);
      onScalarOpacityFunctionChanged();
    }
  }
}

void HistogramWidget::histogramClicked(vtkObject*) {}

void HistogramWidget::updateUI() {}

void HistogramWidget::renderViews()
{

  //  pqView* view =
  //    tomviz::convert<pqView*>(ActiveObjects::instance().activeView());
  //  if (view) {
  //    view->render();
  //  }
}

void HistogramWidget::showEvent(QShowEvent* event)
{
  QWidget::showEvent(event);
  renderViews();
}
} // namespace Avogadro

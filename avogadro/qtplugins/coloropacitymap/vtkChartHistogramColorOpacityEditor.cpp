/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "vtkChartHistogramColorOpacityEditor.h"

#include <vtkAxis.h>
#include <vtkChart.h>
#include <vtkColorTransferControlPointsItem.h>
#include <vtkColorTransferFunction.h>
#include <vtkColorTransferFunctionItem.h>
#include <vtkContextItem.h>
#include <vtkContextScene.h>
#include <vtkObjectFactory.h>
#include <vtkPiecewiseFunction.h>
#include <vtkScalarsToColors.h>
#include <vtkSmartPointer.h>
#include <vtkTable.h>
#include <vtkVector.h>

#include "vtkChartHistogram.h"

class vtkChartHistogramColorOpacityEditor::PIMPL
{
public:
  PIMPL() : Geometry(0, 0), NeedsUpdate(true) {}
  ~PIMPL() {}

  void ForwardEvent(vtkObject* vtkNotUsed(object), unsigned long eventId,
                    void* vtkNotUsed(data))
  {
    this->Self->InvokeEvent(eventId);
  }

  // Cached geometry of the chart
  vtkVector2i Geometry;

  // Dirty bit
  bool NeedsUpdate;

  // Reference to owner of the PIMPL
  vtkChartHistogramColorOpacityEditor* Self;
};

vtkStandardNewMacro(vtkChartHistogramColorOpacityEditor)

  vtkChartHistogramColorOpacityEditor::vtkChartHistogramColorOpacityEditor()
{
  this->Private = new PIMPL();
  this->Private->Self = this;

  this->Borders[vtkAxis::LEFT] = 8;
  this->Borders[vtkAxis::BOTTOM] = 8;
  this->Borders[vtkAxis::RIGHT] = 8;
  this->Borders[vtkAxis::TOP] = 20;

  this->HistogramChart->SetHiddenAxisBorder(10);
  this->HistogramChart->SetLayoutStrategy(vtkChart::AXES_TO_RECT);

  this->ColorTransferFunctionChart->SetBarWidthFraction(1.0);
  this->ColorTransferFunctionChart->SetHiddenAxisBorder(8);
  this->ColorTransferFunctionChart->SetRenderEmpty(true);
  this->ColorTransferFunctionChart->SetAutoAxes(false);
  this->ColorTransferFunctionChart->ZoomWithMouseWheelOff();
  this->ColorTransferFunctionChart->SetLayoutStrategy(vtkChart::AXES_TO_RECT);

  this->ColorTransferFunctionItem->SelectableOff();

  this->ColorTransferControlPointsItem->SetEndPointsXMovable(false);
  this->ColorTransferControlPointsItem->SetEndPointsYMovable(true);
  this->ColorTransferControlPointsItem->SetEndPointsRemovable(false);
  this->ColorTransferControlPointsItem->SelectableOff();

  this->ColorTransferFunctionChart->AddPlot(
    this->ColorTransferFunctionItem.Get());
  this->ColorTransferFunctionChart->SetPlotCorner(
    this->ColorTransferFunctionItem.Get(), 1);
  this->ColorTransferFunctionChart->AddPlot(
    this->ColorTransferControlPointsItem.Get());
  this->ColorTransferFunctionChart->SetPlotCorner(
    this->ColorTransferControlPointsItem.Get(), 1);

  vtkAxis* bottomAxis =
    this->ColorTransferFunctionChart->GetAxis(vtkAxis::BOTTOM);
  bottomAxis->SetTitle("");
  bottomAxis->SetBehavior(vtkAxis::FIXED);
  bottomAxis->SetVisible(false);
  bottomAxis->SetRange(0, 255);

  vtkAxis* leftAxis = this->ColorTransferFunctionChart->GetAxis(vtkAxis::LEFT);
  leftAxis->SetTitle("");
  leftAxis->SetBehavior(vtkAxis::FIXED);
  leftAxis->SetVisible(false);

  vtkAxis* topAxis = this->ColorTransferFunctionChart->GetAxis(vtkAxis::TOP);
  topAxis->SetVisible(false);

  this->AddItem(this->HistogramChart.Get());
  this->AddItem(this->ColorTransferFunctionChart.Get());

  // Forward events from internal charts to observers of this object
  this->HistogramChart->AddObserver(vtkCommand::CursorChangedEvent,
                                    this->Private, &PIMPL::ForwardEvent);
  this->ColorTransferControlPointsItem->AddObserver(
    vtkCommand::EndEvent, this->Private, &PIMPL::ForwardEvent);
  this->ColorTransferControlPointsItem->AddObserver(
    vtkControlPointsItem::CurrentPointEditEvent, this->Private,
    &PIMPL::ForwardEvent);
}

vtkChartHistogramColorOpacityEditor::~vtkChartHistogramColorOpacityEditor()
{
  delete this->Private;
}

void vtkChartHistogramColorOpacityEditor::SetHistogramInputData(
  vtkTable* table, const char* xAxisColumn, const char* yAxisColumn)
{
  this->HistogramChart->SetHistogramInputData(table, xAxisColumn, yAxisColumn);

  if (!table) {
    this->ColorTransferFunctionChart->SetVisible(false);
    return;
  }

  if (!this->ColorTransferFunctionChart->GetVisible()) {
    this->ColorTransferFunctionChart->SetVisible(true);
    this->ColorTransferFunctionChart->RecalculateBounds();
  }

  // The histogram chart bottom axis range was updated in the call above.
  // Set the same range for the color bar bottom axis here.
  vtkAxis* histogramBottomAxis = this->HistogramChart->GetAxis(vtkAxis::BOTTOM);
  double axisRange[2];
  histogramBottomAxis->GetRange(axisRange);

  vtkAxis* bottomAxis =
    this->ColorTransferFunctionChart->GetAxis(vtkAxis::BOTTOM);
  bottomAxis->SetRange(axisRange);

  // The data range may change and cause the labels to change. Hence, update
  // the geometry.
  this->Private->NeedsUpdate = true;
}

void vtkChartHistogramColorOpacityEditor::SetColorTransferFunction(
  vtkColorTransferFunction* ctf)
{
  this->HistogramChart->SetLookupTable(ctf);
  this->ColorTransferFunctionItem->SetColorTransferFunction(ctf);
  this->ColorTransferControlPointsItem->SetColorTransferFunction(ctf);
  this->ColorTransferFunctionChart->RecalculateBounds();
}

void vtkChartHistogramColorOpacityEditor::SetScalarVisibility(bool visible)
{
  this->HistogramChart->SetScalarVisibility(visible);
}

void vtkChartHistogramColorOpacityEditor::SelectColorArray(
  const char* arrayName)
{
  this->HistogramChart->SelectColorArray(arrayName);
}

void vtkChartHistogramColorOpacityEditor::SetOpacityFunction(
  vtkPiecewiseFunction* opacityFunction)
{
  this->HistogramChart->SetOpacityFunction(opacityFunction);
}

vtkAxis* vtkChartHistogramColorOpacityEditor::GetHistogramAxis(int axis)
{
  return this->HistogramChart->GetAxis(axis);
}

bool vtkChartHistogramColorOpacityEditor::GetCurrentControlPointColor(
  double rgb[3])
{
  vtkColorTransferFunction* ctf =
    this->ColorTransferControlPointsItem->GetColorTransferFunction();
  if (!ctf) {
    return false;
  }

  vtkIdType currentIdx =
    this->ColorTransferControlPointsItem->GetCurrentPoint();
  if (currentIdx < 0) {
    return false;
  }

  double xrgbms[6];
  ctf->GetNodeValue(currentIdx, xrgbms);
  rgb[0] = xrgbms[1];
  rgb[1] = xrgbms[2];
  rgb[2] = xrgbms[3];

  return true;
}

void vtkChartHistogramColorOpacityEditor::SetCurrentControlPointColor(
  const double rgb[3])
{
  vtkColorTransferFunction* ctf =
    this->ColorTransferControlPointsItem->GetColorTransferFunction();
  if (!ctf) {
    return;
  }

  vtkIdType currentIdx =
    this->ColorTransferControlPointsItem->GetCurrentPoint();
  if (currentIdx < 0) {
    return;
  }

  double xrgbms[6];
  ctf->GetNodeValue(currentIdx, xrgbms);
  xrgbms[1] = rgb[0];
  xrgbms[2] = rgb[1];
  xrgbms[3] = rgb[2];
  ctf->SetNodeValue(currentIdx, xrgbms);
}

double vtkChartHistogramColorOpacityEditor::GetContourValue()
{
  return this->HistogramChart->GetContourValue();
}

void vtkChartHistogramColorOpacityEditor::SetDPI(int dpi)
{
  if (this->HistogramChart.Get()) {
    this->HistogramChart->SetDPI(dpi);
  }
}

bool vtkChartHistogramColorOpacityEditor::Paint(vtkContext2D* painter)
{
  vtkContextScene* scene = this->GetScene();
  int sceneWidth = scene->GetSceneWidth();
  int sceneHeight = scene->GetSceneHeight();
  if (this->Private->NeedsUpdate ||
      sceneWidth != this->Private->Geometry.GetX() ||
      sceneHeight != this->Private->Geometry.GetY()) {
    this->Private->NeedsUpdate = false;

    // Update the geometry size cache
    this->Private->Geometry.Set(sceneWidth, sceneHeight);

    // Upper chart (histogram) expands, lower chart (color bar) is fixed height.
    float x = this->Borders[vtkAxis::LEFT];
    float y = this->Borders[vtkAxis::BOTTOM];

    // Add the width of the left axis to x to make room for y labels
    this->GetHistogramAxis(vtkAxis::LEFT)->Update();
    float leftAxisWidth = this->GetHistogramAxis(vtkAxis::LEFT)
                            ->GetBoundingRect(painter)
                            .GetWidth();
    x += leftAxisWidth;

    float colorBarThickness = 20;
    float plotWidth = sceneWidth - x - this->Borders[vtkAxis::RIGHT];

    vtkRectf colorTransferFunctionChartSize(x, y, plotWidth, colorBarThickness);
    this->ColorTransferFunctionChart->SetSize(colorTransferFunctionChartSize);
    this->ColorTransferFunctionChart->RecalculateBounds();

    float bottomAxisHeight = this->GetHistogramAxis(vtkAxis::BOTTOM)
                               ->GetBoundingRect(painter)
                               .GetHeight();
    float verticalMargin = bottomAxisHeight;
    y += colorBarThickness + verticalMargin - 5;
    vtkRectf histogramChart(x, y, plotWidth,
                            sceneHeight - y - this->Borders[vtkAxis::TOP]);
    this->HistogramChart->SetSize(histogramChart);
  }

  return this->Superclass::Paint(painter);
}

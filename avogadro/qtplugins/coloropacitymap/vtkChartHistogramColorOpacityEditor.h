/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef tomvizvtkChartHistogramColorOpacityEditor_h
#define tomvizvtkChartHistogramColorOpacityEditor_h

#include <vtkAbstractContextItem.h>
#include <vtkNew.h>

class vtkAxis;
class vtkChartHistogram;
class vtkChartXY;
class vtkColorTransferControlPointsItem;
class vtkColorTransferFunction;
class vtkColorTransferFunctionItem;
class vtkPiecewiseFunction;
class vtkScalarsToColors;
class vtkTable;

// This class is a chart that combines a histogram from a data set
// a color bar editor, and an opacity editor.
class vtkChartHistogramColorOpacityEditor : public vtkAbstractContextItem
{
public:
  vtkTypeMacro(
    vtkChartHistogramColorOpacityEditor,
    vtkAbstractContextItem) static vtkChartHistogramColorOpacityEditor* New();

  // Set the input data.
  void SetHistogramInputData(vtkTable* table, const char* xAxisColumn,
                             const char* yAxisColumn);

  // Set the lookup table.
  void SetColorTransferFunction(vtkColorTransferFunction* lut);

  // Enable or disable scalar visibility.
  virtual void SetScalarVisibility(bool visible);

  // Set the name of the array by which the histogram should be colored.
  virtual void SelectColorArray(const char* arrayName);

  // Set the opacity function.
  virtual void SetOpacityFunction(vtkPiecewiseFunction* opacityFunction);

  // Get an axis from the histogram chart.
  vtkAxis* GetHistogramAxis(int axis);

  // Get the color of the current color control point. Returns true if there
  // is a currently selected control point, false otherwise.
  bool GetCurrentControlPointColor(double rgb[3]);

  // Set the color of the current color control point.
  void SetCurrentControlPointColor(const double rgb[3]);

  // Get the current contour value
  double GetContourValue();

  // Set the DPI
  void SetDPI(int);

  // Paint event for the editor.
  virtual bool Paint(vtkContext2D* painter) override;

protected:
  // This provides the histogram, contour value marker, and opacity editor.
  vtkNew<vtkChartHistogram> HistogramChart;

  // This is used for the color transfer function editor.
  vtkNew<vtkChartXY> ColorTransferFunctionChart;

  // Controls for color transfer function editor.
  vtkNew<vtkColorTransferControlPointsItem> ColorTransferControlPointsItem;

  // Display of color transfer function.
  vtkNew<vtkColorTransferFunctionItem> ColorTransferFunctionItem;

private:
  vtkChartHistogramColorOpacityEditor();
  ~vtkChartHistogramColorOpacityEditor() override;

  class PIMPL;
  PIMPL* Private;

  float Borders[4];
};

#endif // tomvizvtkChartHistogramColorOpacityEditor_h

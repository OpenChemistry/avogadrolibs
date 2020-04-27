/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#ifndef tomvizvtkCustomPiecewiseControlPointsItem_h
#define tomvizvtkCustomPiecewiseControlPointsItem_h

#include <vtkPiecewiseControlPointsItem.h>

class vtkContextMouseEvent;

// Special control points item class that overrides the MouseDoubleClickEvent()
// event handler to do nothing.
class vtkCustomPiecewiseControlPointsItem : public vtkPiecewiseControlPointsItem
{
public:
  vtkTypeMacro(
    vtkCustomPiecewiseControlPointsItem,
    vtkPiecewiseControlPointsItem) static vtkCustomPiecewiseControlPointsItem* New();

  // Override to ignore button presses if the control modifier key is pressed.
  bool MouseButtonPressEvent(const vtkContextMouseEvent& mouse) override;

  // Override to avoid catching double-click events
  bool MouseDoubleClickEvent(const vtkContextMouseEvent& mouse) override;

protected:
  vtkCustomPiecewiseControlPointsItem();
  virtual ~vtkCustomPiecewiseControlPointsItem();

  // Utility function to determine whether a position is near the piecewise
  // function.
  bool PointNearPiecewiseFunction(const double pos[2]);

private:
  vtkCustomPiecewiseControlPointsItem(
    const vtkCustomPiecewiseControlPointsItem&); // Not implemented.
  void operator=(
    const vtkCustomPiecewiseControlPointsItem&); // Not implemented.
};

#endif // tomvizvtkCustomPiecewiseControlPointsItem_h

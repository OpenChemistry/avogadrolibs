/* This source file is part of the Avogadro project.
   It is released under the 3-Clause BSD License, see "LICENSE". */

#include "vtkCustomPiecewiseControlPointsItem.h"

#include <vtkContextMouseEvent.h>
#include <vtkContextScene.h>
#include <vtkObjectFactory.h>
#include <vtkPiecewiseFunction.h>

vtkStandardNewMacro(vtkCustomPiecewiseControlPointsItem)

  vtkCustomPiecewiseControlPointsItem::vtkCustomPiecewiseControlPointsItem()
{}

vtkCustomPiecewiseControlPointsItem::~vtkCustomPiecewiseControlPointsItem() {}

bool vtkCustomPiecewiseControlPointsItem::MouseButtonPressEvent(
  const vtkContextMouseEvent& mouse)
{
  // Ignore middle- and right-click events
  if (mouse.GetButton() != vtkContextMouseEvent::LEFT_BUTTON) {
    return false;
  }

  vtkVector2f vpos = mouse.GetPos();
  this->TransformScreenToData(vpos, vpos);
  double pos[2];
  pos[0] = vpos.GetX();
  pos[1] = vpos.GetY();

  bool pointOnFunction = this->PointNearPiecewiseFunction(pos);
  if (!pointOnFunction) {
    this->SetCurrentPoint(-1);
    return false;
  }

  return this->Superclass::MouseButtonPressEvent(mouse);
}

bool vtkCustomPiecewiseControlPointsItem::MouseDoubleClickEvent(
  const vtkContextMouseEvent& mouse)
{
  // Ignore middle- and right-click events
  if (mouse.GetButton() != vtkContextMouseEvent::LEFT_BUTTON) {
    return false;
  }

  return this->Superclass::MouseDoubleClickEvent(mouse);
}

bool vtkCustomPiecewiseControlPointsItem::PointNearPiecewiseFunction(
  const double position[2])
{
  double x = position[0];
  double y = 0.0;

  vtkPiecewiseFunction* pwf = this->GetPiecewiseFunction();
  if (!pwf) {
    return false;
  }

  // Evaluate the piewewise function at the given point and get the y position.
  // If we are within a small distance of the piecewise function, return true.
  // Otherwise, we are too far away from the line, and return false.
  pwf->GetTable(x, x, 1, &y, 1);
  return (fabs(y - position[1]) < 0.05);
}

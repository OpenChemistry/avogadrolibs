/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_TEXTLABEL2D_H
#define AVOGADRO_RENDERING_TEXTLABEL2D_H

#include "avogadrorenderingexport.h"
#include "textlabelbase.h"

namespace Avogadro {
namespace Rendering {

/**
 * @class TextLabel2D textlabel2d.h <avogadro/rendering/textlabel2d.h>
 * @brief The TextLabel2D class renders text in an overlay plane, anchored to
 * a point in window coordinates.
 */
class AVOGADRORENDERING_EXPORT TextLabel2D : public TextLabelBase
{
public:
  TextLabel2D();
  ~TextLabel2D() override;

  void accept(Visitor&) override;

  /**
   * The anchor point in window coordinates, taking the origin at the upper-left
   * corner.
   * @{
   */
  void setAnchor(const Vector2i& windowCoords);
  Vector2i anchor() const;
  /** @} */
};

} // namespace Rendering
} // namespace Avogadro

#endif // AVOGADRO_RENDERING_TEXTLABEL2D_H

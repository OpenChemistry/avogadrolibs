/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_DRAWABLECOLLECTOR_P_H
#define AVOGADRO_RENDERING_DRAWABLECOLLECTOR_P_H

#include "arrowgeometry.h"
#include "avogadrorendering.h"
#include "curvegeometry.h"
#include "cylindergeometry.h"
#include "dashedlinegeometry.h"
#include "drawable.h"
#include "linestripgeometry.h"
#include "meshgeometry.h"
#include "spheregeometry.h"
#include "textlabel2d.h"
#include "textlabel3d.h"
#include "visitor.h"
#include "volumegeometry.h"
#include "widelinegeometry.h"

#include <array>
#include <vector>

namespace Avogadro::Rendering {

/**
 * @brief Sorts the visible drawables of one scene traversal by render pass.
 *
 * GLRenderer walks the scene once per frame with this visitor instead of once
 * per pass. The buckets keep their capacity from frame to frame, so a steady
 * state frame does not allocate. The pointers are only valid while the scene
 * graph is not modified, so use them within a single render() call.
 *
 * IMPORTANT: this must override visit() for every drawable type that
 * Visitor declares. The base Visitor versions do nothing, so a type that is
 * missed here is silently never rendered. Add new overloads to Visitor and
 * here together; the CollectsEveryDrawableType test covers the list.
 */
class DrawableCollector : public Visitor
{
public:
  static constexpr size_t PassCount = Overlay2DPass + 1;

  void clear()
  {
    for (auto& bucket : m_buckets)
      bucket.clear();
  }

  /** The drawables for @p pass in scene order (empty for NotRendering). */
  const std::vector<Drawable*>& bucket(RenderPass pass) const
  {
    return m_buckets[pass];
  }

  void visit(Drawable& drawable) override { add(drawable); }
  void visit(SphereGeometry& drawable) override { add(drawable); }
  void visit(CurveGeometry& drawable) override { add(drawable); }
  void visit(CylinderGeometry& drawable) override { add(drawable); }
  void visit(MeshGeometry& drawable) override { add(drawable); }
  void visit(TextLabel2D& drawable) override { add(drawable); }
  void visit(TextLabel3D& drawable) override { add(drawable); }
  void visit(LineStripGeometry& drawable) override { add(drawable); }
  void visit(WideLineGeometry& drawable) override { add(drawable); }
  void visit(DashedLineGeometry& drawable) override { add(drawable); }
  void visit(ArrowGeometry& drawable) override { add(drawable); }
  void visit(VolumeGeometry& drawable) override { add(drawable); }

private:
  void add(Drawable& drawable)
  {
    // The same test GLRenderVisitor::shouldRender() makes; drawables that are
    // hidden or not in a known pass never render.
    const RenderPass pass = drawable.renderPass();
    if (drawable.isVisible() && pass != NotRendering && pass < PassCount)
      m_buckets[pass].push_back(&drawable);
  }

  std::array<std::vector<Drawable*>, PassCount> m_buckets;
};

} // namespace Avogadro::Rendering

#endif // AVOGADRO_RENDERING_DRAWABLECOLLECTOR_P_H

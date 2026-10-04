/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_RENDERING_GLRENDERVISITOR_H
#define AVOGADRO_RENDERING_GLRENDERVISITOR_H

#include "visitor.h"

#include "avogadrorendering.h"
#include "camera.h"

namespace Avogadro {
namespace Rendering {
class TextRenderStrategy;

/**
 * @class GLRenderVisitor glrendervisitor.h
 * <avogadro/rendering/glrendervisitor.h>
 * @brief Visitor that takes care of rendering the scene.
 * @author Marcus D. Hanwell
 *
 * This visitor will render elements in the scene.
 */

class AVOGADRORENDERING_EXPORT GLRenderVisitor : public Visitor
{
public:
  explicit GLRenderVisitor(const Camera& camera = Camera(),
                           const TextRenderStrategy* trs = nullptr);
  ~GLRenderVisitor() override;

  /**
   * The current stage of a multipass rendering.
   * @sa Rendering::RenderPass
   * @{
   */
  void setRenderPass(RenderPass pass) { m_renderPass = pass; }
  RenderPass renderPass() const { return m_renderPass; }
  /** @} */

  /**
   * The overloaded visit functions, the base versions of which do nothing.
   */
  void visit(Node&) override { return; }
  void visit(GroupNode&) override { return; }
  void visit(GeometryNode&) override { return; }
  void visit(Drawable&) override;
  void visit(SphereGeometry&) override;
  void visit(CurveGeometry&) override;
  void visit(CylinderGeometry&) override;
  void visit(MeshGeometry&) override;
  void visit(TextLabel2D& geometry) override;
  void visit(TextLabel3D& geometry) override;
  void visit(LineStripGeometry& geometry) override;
  void visit(WideLineGeometry& geometry) override;
  void visit(DashedLineGeometry& geometry) override;
  void visit(ArrowGeometry& geometry) override;
  void visit(VolumeGeometry& geometry) override;

  void setCamera(const Camera& camera_) { m_camera = camera_; }
  Camera camera() const { return m_camera; }

  /**
   * A TextRenderStrategy implementation used to render text for annotations.
   * If nullptr, no text will be produced.
   * @{
   */
  void setTextRenderStrategy(TextRenderStrategy* trs)
  {
    m_textRenderStrategy = trs;
  }
  const TextRenderStrategy* textRenderStrategy() const
  {
    return m_textRenderStrategy;
  }
  /** @} */

  /**
   * The ratio of device pixels to logical pixels. Text labels are rasterized
   * at this scale so they stay sharp on high-DPI displays.
   * @{
   */
  void setPixelRatio(float ratio) { m_pixelRatio = ratio; }
  float pixelRatio() const { return m_pixelRatio; }
  /** @} */

private:
  Camera m_camera;
  const TextRenderStrategy* m_textRenderStrategy;
  RenderPass m_renderPass;
  float m_pixelRatio = 1.0f;
};

} // End namespace Rendering
} // End namespace Avogadro

#endif // AVOGADRO_RENDERING_GLRENDERVISITOR_H

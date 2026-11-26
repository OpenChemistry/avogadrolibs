/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/drawable.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/glrenderer.h>
#include <avogadro/rendering/glrendervisitor.h>
#include <avogadro/rendering/groupnode.h>
#include <avogadro/rendering/spheregeometry.h>

#include <initializer_list>

using Avogadro::Rendering::Camera;
using Avogadro::Rendering::Drawable;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::GLRenderer;
using Avogadro::Rendering::GLRenderVisitor;
using Avogadro::Rendering::OpaquePass;
using Avogadro::Rendering::Orthographic;
using Avogadro::Rendering::Perspective;

namespace {

// No GL context is needed: the projection matrix is plain math on the camera.
void setUp(GLRenderer& renderer, int w, int h, bool perspective)
{
  renderer.camera().setViewport(w, h);
  renderer.camera().setProjectionType(perspective ? Perspective : Orthographic);
}

} // namespace

TEST(GLRendererTest, projectionScaleDefaultsToOne)
{
  GLRenderer renderer;
  EXPECT_FLOAT_EQ(renderer.projectionScale(), 1.0f);
}

TEST(GLRendererTest, perspectiveScaleWidensFrustum)
{
  GLRenderer renderer;
  setUp(renderer, 300, 200, true);
  renderer.applyProjection();
  Eigen::Matrix4f base = renderer.camera().projection().matrix();

  renderer.setProjectionScale(2.0f);
  renderer.applyProjection();
  Eigen::Matrix4f scaled = renderer.camera().projection().matrix();

  // x and y focal terms halve; depth terms are untouched.
  EXPECT_NEAR(scaled(0, 0), base(0, 0) / 2.0f, 1e-5f);
  EXPECT_NEAR(scaled(1, 1), base(1, 1) / 2.0f, 1e-5f);
  EXPECT_FLOAT_EQ(scaled(2, 2), base(2, 2));
  EXPECT_FLOAT_EQ(scaled(2, 3), base(2, 3));
}

TEST(GLRendererTest, orthographicScaleWidensFrustum)
{
  GLRenderer renderer;
  setUp(renderer, 300, 200, false);
  renderer.applyProjection();
  Eigen::Matrix4f base = renderer.camera().projection().matrix();

  renderer.setProjectionScale(1.5f);
  renderer.applyProjection();
  Eigen::Matrix4f scaled = renderer.camera().projection().matrix();

  EXPECT_NEAR(scaled(0, 0), base(0, 0) / 1.5f, 1e-5f);
  EXPECT_NEAR(scaled(1, 1), base(1, 1) / 1.5f, 1e-5f);
  EXPECT_FLOAT_EQ(scaled(2, 2), base(2, 2));
}

TEST(GLRendererTest, projectionScaleDoesNotAccumulate)
{
  for (bool perspective : { true, false }) {
    GLRenderer renderer;
    setUp(renderer, 300, 200, perspective);
    renderer.setProjectionScale(2.0f);
    renderer.applyProjection();
    Eigen::Matrix4f first = renderer.camera().projection().matrix();
    auto frustumBefore = perspective ? renderer.m_perspectiveFrustum
                                     : renderer.m_orthographicFrustum;
    for (int i = 0; i < 5; ++i)
      renderer.applyProjection();
    Eigen::Matrix4f later = renderer.camera().projection().matrix();
    EXPECT_TRUE(first.isApprox(later, 1e-6f));
    // The stored base frustum is not modified by the scale.
    auto frustumAfter = perspective ? renderer.m_perspectiveFrustum
                                    : renderer.m_orthographicFrustum;
    for (int i = 0; i < 4; ++i)
      EXPECT_FLOAT_EQ(frustumBefore[i], frustumAfter[i]);

    // Back to 1 restores the original projection exactly.
    GLRenderer reference;
    setUp(reference, 300, 200, perspective);
    reference.applyProjection();
    renderer.setProjectionScale(1.0f);
    renderer.applyProjection();
    EXPECT_TRUE(renderer.camera().projection().matrix().isApprox(
      reference.camera().projection().matrix(), 1e-6f));
  }
}

TEST(GLRendererTest, scaleKeepsAspectRatio)
{
  GLRenderer renderer;
  setUp(renderer, 400, 100, true);
  renderer.setProjectionScale(3.0f);
  renderer.applyProjection();
  Eigen::Matrix4f m = renderer.camera().projection().matrix();
  // x/y focal ratio is the inverse aspect ratio whatever the scale.
  EXPECT_NEAR(m(1, 1) / m(0, 0), 4.0f, 1e-4f);
}

TEST(GLRendererTest, overlayCameraIsDistinctFromMainCamera)
{
  GLRenderer renderer;
  const GLRenderer& constRenderer = renderer;
  EXPECT_NE(&renderer.overlayCamera(), &renderer.camera());
  EXPECT_NE(&constRenderer.overlayCamera(), &constRenderer.camera());
  EXPECT_EQ(&constRenderer.overlayCamera(), &renderer.overlayCamera());

  renderer.camera().setViewport(640, 480);
  renderer.overlayCamera().setViewport(320, 200);
  EXPECT_EQ(renderer.camera().width(), 640);
  EXPECT_EQ(renderer.camera().height(), 480);
  EXPECT_EQ(renderer.overlayCamera().width(), 320);
  EXPECT_EQ(renderer.overlayCamera().height(), 200);

  renderer.applyProjection();
  EXPECT_TRUE(renderer.overlayCamera().isOrthographic());
  EXPECT_FALSE(renderer.camera().isOrthographic());
}

TEST(GLRendererTest, renderVisitorSkipsHiddenDrawables)
{
  class CountingDrawable : public Drawable
  {
  public:
    int renderCalls = 0;
    void render(const Camera&) override { ++renderCalls; }
  };

  GeometryNode node;
  auto* visible = new CountingDrawable;
  visible->setRenderPass(OpaquePass);
  auto* hidden = new CountingDrawable;
  hidden->setRenderPass(OpaquePass);
  hidden->setVisible(false);
  node.addDrawable(visible);
  node.addDrawable(hidden);

  GLRenderVisitor visitor;
  visitor.setRenderPass(OpaquePass);
  node.accept(visitor);

  EXPECT_EQ(visible->renderCalls, 1);
  EXPECT_EQ(hidden->renderCalls, 0);
}

TEST(GLRendererTest, solidPipelineAntiAliasingSettings)
{
  GLRenderer renderer;
  auto& pipeline = renderer.solidPipeline();

  // FXAA is opt-in, and on its own it is not an effect: the pipeline stays
  // inactive, as it was without it.
  EXPECT_FALSE(pipeline.antiAliasingEnabled());
  pipeline.setFogEnabled(false);
  ASSERT_FALSE(pipeline.hasActiveEffects());
  pipeline.setAntiAliasingEnabled(true);
  EXPECT_TRUE(pipeline.antiAliasingEnabled());
  EXPECT_FALSE(pipeline.hasActiveEffects());
  pipeline.setAntiAliasingEnabled(false);
  EXPECT_FALSE(pipeline.antiAliasingEnabled());

  // Supersampling the edge outline is on until it is switched off.
  EXPECT_TRUE(pipeline.edgeSupersampling());
  pipeline.setEdgeSupersampling(false);
  EXPECT_FALSE(pipeline.edgeSupersampling());
  pipeline.setEdgeSupersampling(true);
  EXPECT_TRUE(pipeline.edgeSupersampling());
}

TEST(GLRendererTest, solidPipelineHasActiveEffects)
{
  GLRenderer renderer;
  auto& pipeline = renderer.solidPipeline();

  // Fog defaults to enabled.
  EXPECT_TRUE(pipeline.getFogEnabled());
  EXPECT_TRUE(pipeline.hasActiveEffects());

  pipeline.setFogEnabled(false);
  EXPECT_FALSE(pipeline.hasActiveEffects());
  // begin() returns false both because no effects are active and because the
  // pipeline has not been initialized.
  EXPECT_FALSE(pipeline.begin());

  pipeline.setAoEnabled(true);
  EXPECT_TRUE(pipeline.hasActiveEffects());
  pipeline.setAoEnabled(false);
  EXPECT_FALSE(pipeline.hasActiveEffects());

  pipeline.setEdEnabled(true);
  EXPECT_TRUE(pipeline.hasActiveEffects());
  pipeline.setEdEnabled(false);
  EXPECT_FALSE(pipeline.hasActiveEffects());

  pipeline.setDofEnabled(true);
  EXPECT_TRUE(pipeline.hasActiveEffects());
  pipeline.setDofEnabled(false);
  EXPECT_FALSE(pipeline.hasActiveEffects());
}

TEST(GLRendererTest, cleanupWithoutGLContextIsNoOp)
{
  GLRenderer renderer;
  renderer.cleanup();
  renderer.solidPipeline().releaseResources();
  EXPECT_FALSE(renderer.solidPipeline().begin());
}

// Picking is CPU math on the camera and the drawables: no GL context needed.
TEST(GLRendererTest, hiddenNodesAreNotPicked)
{
  using Avogadro::Rendering::GroupNode;
  using Avogadro::Rendering::SphereGeometry;
  GLRenderer renderer;
  renderer.camera().setViewport(100, 100);
  auto* group = new GroupNode;
  auto* inner = new GroupNode;
  auto* geometry = new GeometryNode;
  auto* spheres = new SphereGeometry;
  int owner = 0;
  spheres->identifier().molecule = &owner;
  spheres->identifier().type = Avogadro::Rendering::AtomType;
  spheres->addSphere(Avogadro::Vector3f(0, 0, 0),
                     Avogadro::Vector3ub(255, 0, 0), 1.0f);
  renderer.scene().rootNode().addChild(group);
  group->addChild(inner);
  inner->addChild(geometry);
  geometry->addDrawable(spheres);
  renderer.resetCamera();
  renderer.applyProjection();

  EXPECT_FALSE(renderer.hits(50, 50).empty());
  EXPECT_FALSE(renderer.hits(0, 0, 100, 100).empty());

  // Hidden at any level of the subtree: no hits from any picking path.
  for (Avogadro::Rendering::Node* hidden :
       std::initializer_list<Avogadro::Rendering::Node*>{ group, inner,
                                                          geometry }) {
    hidden->setVisible(false);
    EXPECT_TRUE(renderer.hits(50, 50).empty());
    EXPECT_TRUE(renderer.hits(0, 0, 100, 100).empty());
    hidden->setVisible(true);
    EXPECT_FALSE(renderer.hits(50, 50).empty());
    EXPECT_FALSE(renderer.hits(0, 0, 100, 100).empty());
  }
}

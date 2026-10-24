/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/camera.h>
#include <avogadro/rendering/glrenderer.h>

using Avogadro::Rendering::GLRenderer;
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

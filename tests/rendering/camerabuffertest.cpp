/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

// These tests make no GL calls: there is no GL context here.

#include <gtest/gtest.h>

#include <camerabuffer_p.h>

#include <avogadro/rendering/camera.h>

#include <cmath>
#include <cstddef>
#include <cstring>
#include <string>

using Avogadro::Matrix3f;
using Avogadro::Matrix4f;
using Avogadro::Vector3f;
using Avogadro::Rendering::Camera;
using Avogadro::Rendering::CameraBlock;
using Avogadro::Rendering::cameraBlockGlsl;
using Avogadro::Rendering::CameraBlockState;
using Avogadro::Rendering::CameraBufferBindingPoint;
using Avogadro::Rendering::insertCameraBlock;
using Avogadro::Rendering::StyleBufferBindingPoint;

namespace {

Camera makeCamera()
{
  Camera camera;
  camera.setViewport(200, 100);
  camera.translate(Vector3f(0.5f, -1.0f, -10.0f));
  camera.rotate(30.0f, Vector3f(1.0f, 2.0f, 3.0f).normalized());
  camera.calculatePerspective(40.0f, 0.5f, 100.0f);
  return camera;
}

bool allFinite(const CameraBlock& block)
{
  const float* values = reinterpret_cast<const float*>(&block);
  for (std::size_t i = 0; i < sizeof(block) / sizeof(float); ++i) {
    if (!std::isfinite(values[i]))
      return false;
  }
  return true;
}

} // namespace

TEST(CameraBufferTest, std140LayoutMatchesTheGlslBlock)
{
  // The static_asserts in the header check these at compile time; this keeps
  // the numbers in the test log too.
  EXPECT_EQ(offsetof(CameraBlock, modelView), 0u);
  EXPECT_EQ(offsetof(CameraBlock, projection), 64u);
  EXPECT_EQ(offsetof(CameraBlock, inverseProjection), 128u);
  EXPECT_EQ(offsetof(CameraBlock, normalMatrix), 192u);
  EXPECT_EQ(offsetof(CameraBlock, viewport), 256u);
  EXPECT_EQ(offsetof(CameraBlock, cameraParams), 272u);
  EXPECT_EQ(offsetof(CameraBlock, sceneBounds), 288u);
  EXPECT_EQ(sizeof(CameraBlock), 304u);
  EXPECT_NE(CameraBufferBindingPoint, StyleBufferBindingPoint);
}

TEST(CameraBufferTest, glslDeclaresTheMembersInOrder)
{
  const std::string glsl = cameraBlockGlsl();
  std::size_t at = glsl.find("std140");
  ASSERT_NE(at, std::string::npos);
  for (const char* name :
       { "modelView", "projection", "inverseProjection", "normalMatrix",
         "viewport", "cameraParams", "sceneBounds" }) {
    const std::size_t next = glsl.find(std::string(" ") + name + ";", at);
    ASSERT_NE(next, std::string::npos) << name;
    at = next;
  }
}

TEST(CameraBufferTest, blockIsInsertedAfterTheVersionLine)
{
  const std::string source =
    "#version 400\nprecision highp float;\nvoid main(){}\n";
  const std::string result = insertCameraBlock(source);
  const std::string block = cameraBlockGlsl();
  EXPECT_EQ(result, "#version 400\n" + block +
                      "precision highp float;\nvoid main(){}\n");
  // Without a version line it goes first; with only a version line, after it.
  EXPECT_EQ(insertCameraBlock("void main(){}\n"), block + "void main(){}\n");
  EXPECT_EQ(insertCameraBlock("#version 400"), "#version 400\n" + block);
}

TEST(CameraBufferTest, buildCopiesTheCameraMatrices)
{
  const Camera camera = makeCamera();
  const Vector3f center(1.0f, 2.0f, 3.0f);
  const CameraBlock block = CameraBlockState::build(camera, 2.0f, center, 7.5f);

  EXPECT_EQ(0, std::memcmp(block.modelView, camera.modelView().matrix().data(),
                           sizeof(block.modelView)));
  EXPECT_EQ(0,
            std::memcmp(block.projection, camera.projection().matrix().data(),
                        sizeof(block.projection)));

  // The normal matrix is the expression the drawables used to evaluate.
  const Matrix3f expected = camera.modelView().linear().inverse().transpose();
  Matrix4f normal;
  std::memcpy(normal.data(), block.normalMatrix, sizeof(block.normalMatrix));
  EXPECT_EQ(0, std::memcmp(normal.topLeftCorner<3, 3>().eval().data(),
                           expected.data(), 9 * sizeof(float)));

  Matrix4f inverse;
  std::memcpy(inverse.data(), block.inverseProjection,
              sizeof(block.inverseProjection));
  const Matrix4f product = inverse * camera.projection().matrix();
  EXPECT_LT((product - Matrix4f::Identity()).cwiseAbs().maxCoeff(), 1e-4f);

  EXPECT_FLOAT_EQ(block.viewport[0], 400.0f);
  EXPECT_FLOAT_EQ(block.viewport[1], 200.0f);
  EXPECT_FLOAT_EQ(block.viewport[2], 1.0f / 400.0f);
  EXPECT_FLOAT_EQ(block.viewport[3], 1.0f / 200.0f);
  EXPECT_FLOAT_EQ(block.cameraParams[0], 2.0f);
  EXPECT_NEAR(block.cameraParams[1], 0.5f, 1e-4f);
  EXPECT_NEAR(block.cameraParams[2], 100.0f, 1e-2f);
  EXPECT_FLOAT_EQ(block.cameraParams[3], 0.0f);
  EXPECT_FLOAT_EQ(block.sceneBounds[0], 1.0f);
  EXPECT_FLOAT_EQ(block.sceneBounds[1], 2.0f);
  EXPECT_FLOAT_EQ(block.sceneBounds[2], 3.0f);
  EXPECT_FLOAT_EQ(block.sceneBounds[3], 7.5f);
}

TEST(CameraBufferTest, orthographicCameraIsFlagged)
{
  Camera camera;
  camera.setViewport(100, 100);
  camera.calculateOrthographic(-5.0f, 5.0f, -5.0f, 5.0f, -10.0f, 10.0f);
  const CameraBlock block =
    CameraBlockState::build(camera, 1.0f, Vector3f::Zero(), 0.0f);
  EXPECT_FLOAT_EQ(block.cameraParams[3], 1.0f);
  EXPECT_TRUE(allFinite(block));
}

TEST(CameraBufferTest, degenerateCamerasNeverProduceNonFiniteValues)
{
  // No viewport: width and height are 0.
  Camera noViewport;
  noViewport.setViewport(0, 0);
  CameraBlock block =
    CameraBlockState::build(noViewport, 1.0f, Vector3f::Zero(), 0.0f);
  EXPECT_TRUE(allFinite(block));
  EXPECT_EQ(block.viewport[2], 0.0f);
  EXPECT_EQ(block.viewport[3], 0.0f);

  // A zero projection and a zero model view are singular.
  Camera singular;
  singular.setViewport(10, 10);
  singular.setProjection(Eigen::Affine3f(Matrix4f::Zero().eval()));
  singular.setModelView(Eigen::Affine3f(Matrix4f::Zero().eval()));
  block = CameraBlockState::build(singular, 1.0f, Vector3f::Zero(), 0.0f);
  EXPECT_TRUE(allFinite(block));

  // Non-finite frame parameters become neutral values.
  CameraBlockState state;
  state.setFrameParameters(std::nanf(""), Vector3f::Constant(INFINITY), -1.0f);
  state.update(makeCamera());
  EXPECT_TRUE(allFinite(state.block()));
  EXPECT_FLOAT_EQ(state.block().cameraParams[0], 1.0f);
  EXPECT_FLOAT_EQ(state.block().sceneBounds[3], 0.0f);
}

TEST(CameraBufferTest, updateRebuildsOnlyWhenSomethingChanged)
{
  CameraBlockState state;
  Camera camera = makeCamera();
  EXPECT_TRUE(state.update(camera));        // The first update always builds.
  EXPECT_FALSE(state.update(camera));       // Same camera: nothing to upload.
  EXPECT_FALSE(state.update(makeCamera())); // Equal values, another object.

  camera.translate(Vector3f(0.0f, 0.0f, 1.0f));
  EXPECT_TRUE(state.update(camera));
  EXPECT_FALSE(state.update(camera));

  camera.calculatePerspective(50.0f, 0.5f, 100.0f);
  EXPECT_TRUE(state.update(camera));
  EXPECT_FALSE(state.update(camera));

  camera.setViewport(300, 100);
  EXPECT_TRUE(state.update(camera));
  EXPECT_FALSE(state.update(camera));

  state.invalidate();
  EXPECT_TRUE(state.update(camera));
}

TEST(CameraBufferTest, frameParametersSurviveACameraSwitch)
{
  CameraBlockState state;
  state.setFrameParameters(2.0f, Vector3f(1.0f, 2.0f, 3.0f), 5.0f);
  const Camera main = makeCamera();
  EXPECT_TRUE(state.update(main));

  // A drawable renders with another camera (the 2D overlay) and the next one
  // with the main camera again: the scene bounds and pixel ratio stay.
  Camera overlay;
  overlay.setViewport(200, 100);
  overlay.calculateOrthographic(0.0f, 200.0f, 0.0f, 100.0f, -1.0f, 1.0f);
  EXPECT_TRUE(state.update(overlay));
  EXPECT_FLOAT_EQ(state.block().cameraParams[0], 2.0f);
  EXPECT_FLOAT_EQ(state.block().cameraParams[3], 1.0f);
  EXPECT_FLOAT_EQ(state.block().sceneBounds[3], 5.0f);
  EXPECT_TRUE(state.update(main));
  EXPECT_FLOAT_EQ(state.block().cameraParams[3], 0.0f);
  EXPECT_FLOAT_EQ(state.block().sceneBounds[2], 3.0f);

  // Unchanged frame parameters do not force a rebuild; changed ones do.
  state.setFrameParameters(2.0f, Vector3f(1.0f, 2.0f, 3.0f), 5.0f);
  EXPECT_FALSE(state.update(main));
  state.setFrameParameters(2.0f, Vector3f(1.0f, 2.0f, 3.0f), 6.0f);
  EXPECT_TRUE(state.update(main));
  EXPECT_FLOAT_EQ(state.block().sceneBounds[3], 6.0f);
}

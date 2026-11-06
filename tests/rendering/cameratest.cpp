/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/camera.h>

#include <Eigen/Geometry>

#include <cmath>
#include <iostream>

using Avogadro::Vector2f;
using Avogadro::Vector3f;
using Avogadro::Rendering::Camera;

void setUpOrthographic(Camera& camera)
{
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
}

TEST(CameraTest, perspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);

  // Load in a known value for the result of this matrix.
  Eigen::Matrix4f expected;
  expected << 1.83165f, 0.0f, 0.0f, 0.0f, 0.0f, 2.74748f, 0.0f, 0.0f, 0.0f,
    0.0f, -1.22222f, -2.22222f, 0.0f, 0.0f, -1.0f, 0.0f;
  EXPECT_TRUE(camera.projection().matrix().isApprox(expected));
  // If it is incorrect then print out the result.
  if (!camera.projection().matrix().isApprox(expected)) {
    std::cout << "Error: No match\n"
              << camera.projection().matrix() << "\nexpected\n"
              << expected << std::endl;
  }
}

TEST(CameraTest, orthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);

  // Load in a known value for the result of this matrix.
  Eigen::Matrix4f expected;
  expected << 0.2f, 0.0f, 0.0f, -1.0f, 0.0f, 0.2f, 0.0f, -1.0f, 0.0f, 0.0f,
    -2.0f, -1.0f, 0.0f, 0.0f, 0.0f, 1.0f;
  EXPECT_TRUE(camera.projection().matrix().isApprox(expected));
  // If it is incorrect then print out the result.
  if (!camera.projection().matrix().isApprox(expected)) {
    std::cout << "Error: No match\n"
              << camera.projection().matrix() << "\nexpected\n"
              << expected << std::endl;
  }
}

TEST(CameraTest, projectOrthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
  camera.setViewport(100, 100);

  Vector3f position = camera.project(Vector3f(1.0, 2.0, 0.0));
  Vector3f expected(10.0, 20.0, 0.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, projectPerspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);
  camera.preTranslate(Vector3f(0, 0, -10));
  camera.setViewport(100, 100);

  Vector3f position = camera.project(Vector3f(1.0, 2.0, 0.0));
  Vector3f expected(59.1583f, 77.4748f, 1.0f);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, unProjectOrthographic)
{
  Camera camera;
  camera.calculateOrthographic(0, 10, 0, 10, 0, 1);
  camera.setViewport(100, 100);

  Vector3f position = camera.unProject(Vector3f(10, 25, 0));
  Vector3f expected(1.0, 7.5, 0.0);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, unProjectPerspective)
{
  Camera camera;
  camera.calculatePerspective(40, 1.5, 1, 10);
  camera.preTranslate(Vector3f(0, 0, -10));
  camera.setViewport(100, 100);

  Vector3f position = camera.unProject(Vector3f(10, 25, 0));
  Vector3f expected(-0.436764f, 0.181985f, 9.0f);
  EXPECT_TRUE(position.isApprox(expected));
  if (!position.isApprox(expected)) {
    std::cout << "Error: No match\n" << position << std::endl;
  }
}

TEST(CameraTest, perspectiveParametersRoundTrip)
{
  Camera camera;
  camera.calculatePerspective(40.0f, 1.5f, 0.5f, 100.0f);
  EXPECT_FALSE(camera.isOrthographic());
  EXPECT_NEAR(camera.verticalFieldOfView(), 40.0f, 1e-4f);
  EXPECT_NEAR(camera.aspectRatio(), 1.5f, 1e-5f);
  EXPECT_NEAR(camera.nearPlane(), 0.5f, 1e-4f);
  EXPECT_NEAR(camera.farPlane(), 100.0f, 1e-1f);
  EXPECT_EQ(camera.orthographicHalfExtents(), Vector2f::Zero());
}

TEST(CameraTest, orthographicParametersRoundTrip)
{
  Camera camera;
  camera.calculateOrthographic(-2.0f, 2.0f, -1.5f, 1.5f, 0.1f, 50.0f);
  EXPECT_TRUE(camera.isOrthographic());
  EXPECT_NEAR(camera.aspectRatio(), 4.0f / 3.0f, 1e-5f);
  EXPECT_NEAR(camera.nearPlane(), 0.1f, 1e-5f);
  EXPECT_NEAR(camera.farPlane(), 50.0f, 1e-4f);
  const Vector2f half = camera.orthographicHalfExtents();
  EXPECT_NEAR(half[0], 2.0f, 1e-5f);
  EXPECT_NEAR(half[1], 1.5f, 1e-5f);
  EXPECT_EQ(camera.verticalFieldOfView(), 0.0f);

  // The near plane can be behind the eye; the orthographic scale applies to
  // the half extents.
  camera.setOrthographicScale(2.0f);
  camera.calculateOrthographic(-40.0f, 40.0f, -30.0f, 30.0f, -100.0f, 100.0f);
  EXPECT_NEAR(camera.nearPlane(), -100.0f, 1e-3f);
  EXPECT_NEAR(camera.farPlane(), 100.0f, 1e-3f);
  EXPECT_NEAR(camera.orthographicHalfExtents()[0], 80.0f, 1e-3f);
}

TEST(CameraTest, projectionTypeComesFromTheMatrix)
{
  // Raw matrices do not touch projectionType().
  Camera orthographic;
  orthographic.calculateOrthographic(-1, 1, -1, 1, 0, 10);
  Camera copy;
  copy.setProjection(orthographic.projection());
  EXPECT_TRUE(copy.isOrthographic());
  copy.setProjection(Eigen::Affine3f::Identity());
  EXPECT_TRUE(copy.isOrthographic()); // (3, 3) is 1
}

TEST(CameraTest, viewDecodesLookAtAndZoom)
{
  Camera camera;
  const Vector3f eye(1.0f, 2.0f, 10.0f);
  camera.lookAt(eye, Vector3f(0, 0, 0), Vector3f(0, 1, 0));
  EXPECT_NEAR(camera.viewScale(), 1.0f, 1e-6f);
  EXPECT_TRUE(camera.eyePosition().isApprox(eye, 1e-5f));
  const Eigen::Matrix3f rotation = camera.viewRotation();
  EXPECT_TRUE((rotation * rotation.transpose())
                .isApprox(Eigen::Matrix3f::Identity(), 1e-5f));
  // The camera looks along -Z (its third column points to the viewer).
  EXPECT_TRUE(
    rotation.col(2).isApprox(-(Vector3f(0, 0, 0) - eye).normalized(), 1e-5f));

  // Zooming scales the world (about the origin) before the model view, so
  // the eye is where it maps to the eye-space origin; the rotation is the same.
  camera.scale(1.3f);
  EXPECT_NEAR(camera.viewScale(), 1.3f, 1e-5f);
  EXPECT_TRUE(camera.eyePosition().isApprox(eye / 1.3f, 1e-4f));
  EXPECT_TRUE(camera.viewRotation().isApprox(rotation, 1e-5f));
  // The eye maps to the origin of eye space.
  EXPECT_TRUE((camera.modelView() * camera.eyePosition()).norm() < 1e-4f);
}

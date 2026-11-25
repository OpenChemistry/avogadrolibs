/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>
#include <avogadro/rendering/texture2d.h>

using Avogadro::Vector2i;
using Avogadro::Vector3f;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;
using Avogadro::Rendering::Texture2D;

TEST(Texture2DTest, defaultsWithoutGLContext)
{
  Texture2D texture;
  EXPECT_EQ(texture.handle(), 0u);
  EXPECT_FALSE(texture.ready());
  EXPECT_EQ(texture.minFilter(), Texture2D::Linear);
  EXPECT_EQ(texture.magFilter(), Texture2D::Linear);
  EXPECT_EQ(texture.wrappingS(), Texture2D::Repeat);
  EXPECT_EQ(texture.wrappingT(), Texture2D::Repeat);
}

TEST(Texture2DTest, setParametersDeferredWithoutGLContext)
{
  Texture2D texture;
  texture.setMinFilter(Texture2D::Nearest);
  texture.setMagFilter(Texture2D::Nearest);
  texture.setWrappingS(Texture2D::ClampToEdge);
  texture.setWrappingT(Texture2D::MirroredRepeat);

  // Parameters are cached on the CPU without creating a GL handle.
  EXPECT_EQ(texture.handle(), 0u);
  EXPECT_FALSE(texture.ready());
  EXPECT_EQ(texture.minFilter(), Texture2D::Nearest);
  EXPECT_EQ(texture.magFilter(), Texture2D::Nearest);
  EXPECT_EQ(texture.wrappingS(), Texture2D::ClampToEdge);
  EXPECT_EQ(texture.wrappingT(), Texture2D::MirroredRepeat);
}

TEST(Texture2DTest, invalidParametersIgnored)
{
  Texture2D texture;
  texture.setMinFilter(Texture2D::Nearest);
  texture.setMagFilter(Texture2D::Nearest);
  texture.setWrappingS(Texture2D::ClampToEdge);
  texture.setWrappingT(Texture2D::MirroredRepeat);

  texture.setMinFilter(Texture2D::InvalidFilter);
  texture.setMagFilter(Texture2D::InvalidFilter);
  texture.setWrappingS(Texture2D::InvalidWrapping);
  texture.setWrappingT(Texture2D::InvalidWrapping);

  EXPECT_EQ(texture.minFilter(), Texture2D::Nearest);
  EXPECT_EQ(texture.magFilter(), Texture2D::Nearest);
  EXPECT_EQ(texture.wrappingS(), Texture2D::ClampToEdge);
  EXPECT_EQ(texture.wrappingT(), Texture2D::MirroredRepeat);
}

TEST(Texture2DTest, textLabelsConstructWithoutGLContext)
{
  // TextLabelBase configures its internal Texture2D in its constructor; lazy
  // GL initialization allows constructing and copying labels without a context.
  TextProperties props;
  props.setPixelHeight(18);
  props.setColorRgb(200, 100, 50);

  TextLabel2D label2d;
  label2d.setText("2D Label");
  label2d.setAnchor(Vector2i(10, 20));
  label2d.setTextProperties(props);
  TextLabel2D copy2d(label2d);
  EXPECT_EQ(copy2d.text(), "2D Label");
  EXPECT_EQ(copy2d.anchor(), Vector2i(10, 20));

  TextLabel3D label3d;
  label3d.setText("C1");
  label3d.setAnchor(Vector3f(1.f, 2.f, 3.f));
  label3d.setRadius(0.5f);
  label3d.setTextProperties(props);
  TextLabel3D copy3d(label3d);
  EXPECT_EQ(copy3d.text(), "C1");
  EXPECT_EQ(copy3d.anchor(), Vector3f(1.f, 2.f, 3.f));
  EXPECT_FLOAT_EQ(copy3d.radius(), 0.5f);
}

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/contrastcolor.h>
#include <avogadro/core/elements.h>

using Avogadro::Vector3ub;
using Avogadro::Core::contrastColor;
using Avogadro::Core::contrastRatio;
using Avogadro::Core::Elements;
using Avogadro::Core::relativeLuminance;

namespace {
const Vector3ub black(0, 0, 0);
const Vector3ub white(255, 255, 255);
} // namespace

TEST(ContrastColorTest, extremes)
{
  EXPECT_EQ(contrastColor(white), black);
  EXPECT_EQ(contrastColor(black), white);
  EXPECT_EQ(contrastColor(Vector3ub(240, 240, 240)), black);
}

TEST(ContrastColorTest, previouslyFailingElements)
{
  const Vector3ub colors[] = { Vector3ub(255, 13, 13), Vector3ub(255, 128, 0),
                               Vector3ub(48, 80, 255), Vector3ub(31, 240, 31) };
  for (const auto& c : colors)
    EXPECT_GE(contrastRatio(c, contrastColor(c)), 4.5);
}

TEST(ContrastColorTest, allElements)
{
  for (unsigned char i = 0; i < Avogadro::Core::element_count; ++i) {
    const unsigned char* raw = Elements::color(i);
    const Vector3ub c(raw[0], raw[1], raw[2]);
    EXPECT_GE(contrastRatio(c, contrastColor(c)), 4.5) << "element " << int(i);
  }
}

TEST(ContrastColorTest, relativeLuminance)
{
  EXPECT_NEAR(relativeLuminance(black), 0.0, 1e-9);
  EXPECT_NEAR(relativeLuminance(white), 1.0, 1e-9);
  EXPECT_NEAR(relativeLuminance(Vector3ub(128, 128, 128)), 0.2158, 1e-3);
}

TEST(ContrastColorTest, resultIsBlackOrWhite)
{
  for (int r = 0; r < 256; r += 51)
    for (int g = 0; g < 256; g += 51)
      for (int b = 0; b < 256; b += 51) {
        const Vector3ub result = contrastColor(Vector3ub(r, g, b));
        EXPECT_TRUE(result == black || result == white);
      }
}

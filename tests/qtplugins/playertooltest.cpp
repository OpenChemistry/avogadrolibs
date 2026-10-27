/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <playertool.h>

#include <QtWidgets/QSpinBox>
#include <QtWidgets/QWidget>

using Avogadro::QtPlugins::PlayerTool;

namespace {

QSpinBox* frameRateControl(QWidget* widget)
{
  for (auto* spinBox : widget->findChildren<QSpinBox*>()) {
    if (spinBox->suffix().trimmed() == QStringLiteral("FPS"))
      return spinBox;
  }
  return nullptr;
}

} // namespace

TEST(PlayerToolCommandTest, FrameRateRejectsNonpositiveValues)
{
  QWidget parent;
  PlayerTool tool(&parent);
  auto* frameRate = frameRateControl(tool.toolWidget());
  ASSERT_NE(frameRate, nullptr);

  frameRate->setValue(0);
  EXPECT_GT(frameRate->value(), 0);

  frameRate->setValue(-1);
  EXPECT_GT(frameRate->value(), 0);
}

TEST(PlayerToolCommandTest, PreservesSupportedFrameRates)
{
  QWidget parent;
  PlayerTool tool(&parent);
  auto* frameRate = frameRateControl(tool.toolWidget());
  ASSERT_NE(frameRate, nullptr);

  EXPECT_EQ(frameRate->value(), 5);
  for (int fps : { 1, 100, 1000 }) {
    frameRate->setValue(fps);
    EXPECT_EQ(frameRate->value(), fps);
  }
}

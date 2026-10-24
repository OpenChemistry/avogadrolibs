/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtopengl/imagesizedialog.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QSettings>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpinBox>

using Avogadro::QtOpenGL::ImageSizeDialog;

namespace {

const char* const Key = "imageSizeDialogTest";

QApplication* ensureApp()
{
  if (QCoreApplication::instance() != nullptr)
    return qobject_cast<QApplication*>(QCoreApplication::instance());

  static int argc = 1;
  static char arg0[] = "imagesizedialogtest";
  static char* argv[] = { arg0, nullptr };
  if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
    qputenv("QT_QPA_PLATFORM", "offscreen");
  static QApplication app(argc, argv);
  return &app;
}

void clearSettings()
{
  QSettings settings;
  settings.remove(Key);
}

class ImageSizeDialogTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    if (ensureApp() == nullptr)
      GTEST_SKIP() << "A QApplication is required for QWidget tests.";
    clearSettings();
  }
  void TearDown() override { clearSettings(); }

  // No GLWidget: the dialog falls back to an 800 x 600 view.
  static QSpinBox* spin(ImageSizeDialog& d, int index)
  {
    return d.findChildren<QSpinBox*>().at(index);
  }
  static QCheckBox* checkBox(ImageSizeDialog& d, const QString& text)
  {
    for (auto* c : d.findChildren<QCheckBox*>())
      if (c->text().contains(text))
        return c;
    return nullptr;
  }
  static QPushButton* button(ImageSizeDialog& d, const QString& text)
  {
    for (auto* b : d.findChildren<QPushButton*>())
      if (b->text() == text)
        return b;
    return nullptr;
  }
};

} // namespace

TEST_F(ImageSizeDialogTest, defaultsToViewSize)
{
  ImageSizeDialog dialog(nullptr, Key, true, false);
  EXPECT_EQ(dialog.imageSize(), QSize(800, 600));
  EXPECT_FALSE(dialog.transparentBackground());
}

TEST_F(ImageSizeDialogTest, presetsScaleTheView)
{
  ImageSizeDialog dialog(nullptr, Key, false, false);
  ASSERT_NE(button(dialog, QStringLiteral("2×")), nullptr);
  button(dialog, QStringLiteral("2×"))->click();
  EXPECT_EQ(dialog.imageSize(), QSize(1600, 1200));
  button(dialog, QStringLiteral("4×"))->click();
  EXPECT_EQ(dialog.imageSize(), QSize(3200, 2400));
  button(dialog, QStringLiteral("1×"))->click();
  EXPECT_EQ(dialog.imageSize(), QSize(800, 600));
}

TEST_F(ImageSizeDialogTest, aspectLock)
{
  ImageSizeDialog dialog(nullptr, Key, false, false);
  // Locked by default.
  spin(dialog, 0)->setValue(1000);
  EXPECT_EQ(dialog.imageSize(), QSize(1000, 750));
  spin(dialog, 1)->setValue(300);
  EXPECT_EQ(dialog.imageSize(), QSize(400, 300));

  // Unlocked: dimensions are independent, and the new ratio is what a later
  // lock keeps.
  auto* lock = checkBox(dialog, "ock");
  lock->setChecked(false);
  spin(dialog, 0)->setValue(900);
  EXPECT_EQ(dialog.imageSize(), QSize(900, 300));
  lock->setChecked(true);
  spin(dialog, 0)->setValue(600);
  EXPECT_EQ(dialog.imageSize(), QSize(600, 200));
}

TEST_F(ImageSizeDialogTest, evenDimensions)
{
  ImageSizeDialog dialog(nullptr, Key, false, true);
  dialog.setImageSize(QSize(801, 601));
  EXPECT_EQ(dialog.imageSize(), QSize(802, 602));
  auto* lock = checkBox(dialog, "ock");
  lock->setChecked(false);
  spin(dialog, 0)->setValue(1001);
  EXPECT_EQ(spin(dialog, 0)->value() % 2, 0);
  button(dialog, QStringLiteral("1×"))->click();
  EXPECT_EQ(dialog.imageSize(), QSize(800, 600));
}

TEST_F(ImageSizeDialogTest, transparentSurvivesAccept)
{
  {
    ImageSizeDialog dialog(nullptr, Key, true, false);
    QCheckBox* transparent = checkBox(dialog, "ransparent");
    ASSERT_NE(transparent, nullptr);
    transparent->setChecked(true);
    dialog.setImageSize(QSize(640, 480));
    dialog.accept();
    // The dialog is hidden once it has been accepted; the answer must not
    // depend on visibility.
    EXPECT_FALSE(dialog.isVisible());
    EXPECT_TRUE(dialog.transparentBackground());
    EXPECT_TRUE(dialog.renderOptions().transparentBackground);
    EXPECT_EQ(dialog.renderOptions().size, QSize(640, 480));
  }
  // And it is remembered.
  ImageSizeDialog again(nullptr, Key, true, false);
  EXPECT_EQ(again.imageSize(), QSize(640, 480));
  EXPECT_TRUE(again.transparentBackground());
}

TEST_F(ImageSizeDialogTest, transparentHiddenWhenNotOffered)
{
  ImageSizeDialog dialog(nullptr, Key, false, false);
  dialog.accept();
  EXPECT_FALSE(dialog.transparentBackground());
  // The unused check box is still owned by the dialog.
  for (auto* c : dialog.findChildren<QCheckBox*>())
    EXPECT_EQ(c->window(), &dialog);
}

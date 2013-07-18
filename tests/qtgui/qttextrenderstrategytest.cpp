/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>
#include "qtguitests.h"

#include <avogadro/qtgui/qttextrenderstrategy.h>

#include <avogadro/rendering/textproperties.h>

#include <QtGui/QApplication>
#include <QtGui/QImage>

#include <QtCore/QDebug>

#include <string>

typedef Avogadro::QtGui::QtTextRenderStrategy Strategy;
typedef Avogadro::Rendering::TextRenderStrategy Interface;
using Avogadro::Rendering::TextProperties;

// Need to start an app to load fonts
#define START_QAPP \
  int argc = 1; \
  char argName[] = "FakeApp.exe"; \
  char *argv[2] = {argName, NULL}; \
  QApplication app(argc, argv); \
  Q_UNUSED(app)

TEST(QtTextRenderStrategyTest, newInstance)
{
  Strategy orig;
  Interface *clone = orig.newInstance();
  EXPECT_NE(dynamic_cast<Strategy*>(clone), reinterpret_cast<Strategy*>(NULL));
  delete clone;
}

TEST(QtTextRenderStrategyTest, boundingBox)
{
  START_QAPP;

  Strategy strategy;
  TextProperties tprop;
  std::string testString("Testing string\nwith newlines!");
  tprop.setFontFamily(TextProperties::SansSerif);
  tprop.setPointSize(12);
  tprop.setHAlign(TextProperties::HCenter);
  tprop.setVAlign(TextProperties::VCenter);

  int bbox[4];
  int refbbox[4] = {-86, 85, -28, 27};
  strategy.boundingBox(testString, tprop, bbox);
  EXPECT_TRUE(std::equal(bbox, bbox + 4, refbbox));
}

// Helpers for rendering tests:
namespace {
bool compareComponents(unsigned char a, unsigned char b)
{
  // Allow small differences in component values.
  return std::abs(a - b) <= 2;
}

float validateBaseline(unsigned char *buffer, size_t numPixels,
                       const std::string &fileName)
{
  static const std::string baselineDir(
        AVOGADRO_DATA "/baselines/avogadro/qtgui/qttextrenderstrategy/");
  QImage refImage;
  if (!refImage.load(QString::fromStdString(baselineDir + fileName)))
    qWarning() << "Error loading file" << QString::fromStdString(fileName);
  refImage = refImage.convertToFormat(QImage::Format_ARGB32_Premultiplied);
  return std::equal(buffer, buffer + (numPixels * 4), refImage.constBits(),
                    compareComponents);
}

bool testRenderedString(Strategy &strategy, const std::string &str,
                        const TextProperties &tprop,
                        const std::string &refFilename)
{
  int bbox[4];
  strategy.boundingBox(str, tprop, bbox);
  size_t dims[2] = {static_cast<size_t>(bbox[1] - bbox[0] + 1),
                    static_cast<size_t>(bbox[3] - bbox[2] + 1)};
  std::vector<unsigned char> buffer(dims[0] * dims[1] * 4);
  if (buffer.empty())
    return false;
  strategy.render(str, tprop, &buffer[0], dims);
  return validateBaseline(&buffer[0], dims[0] * dims[1], refFilename);
}

// Useful for making new baselines:
void saveRenderedString(Strategy &strategy, const std::string &str,
                        const TextProperties &tprop,
                        const std::string &filename)
{
  int bbox[4];
  strategy.boundingBox(str, tprop, bbox);
  size_t dims[2] = {static_cast<size_t>(bbox[1] - bbox[0] + 1),
                    static_cast<size_t>(bbox[3] - bbox[2] + 1)};
  std::vector<unsigned char> buffer(dims[0] * dims[1] * 4);
  if (buffer.empty())
    return;
  strategy.render(str, tprop, &buffer[0], dims);
  QImage img(&buffer[0], dims[0], dims[1], QImage::Format_ARGB32_Premultiplied);
  img.save(QString::fromStdString(filename));
}

} // end anon namespace

TEST(QtTextRenderStrategyTest, render)
{
  START_QAPP;

  Strategy strategy;
  // Keep the buffer in a format that we can save with a QImage:
  strategy.setPreserveArgb(true);

  std::string str("Testing string\nwith newlines!\nSome lines are longer...");

  TextProperties tprop;
  tprop.setFontFamily(TextProperties::SansSerif);
  tprop.setPointSize(12);
  tprop.setColorRgb(63, 127, 255);
  tprop.setVAlign(TextProperties::VTop);
  tprop.setHAlign(TextProperties::HLeft);

  EXPECT_TRUE(testRenderedString(strategy, str, tprop, "renderedString1.png"));

  tprop.setRotationDegreesCW(25);
  tprop.setRed(255);
  tprop.setBlue(63);
  tprop.setAlpha(200);
  tprop.setVAlign(TextProperties::VCenter);
  tprop.setHAlign(TextProperties::HCenter);
  tprop.setItalic(true);
  tprop.setBold(true);

  EXPECT_TRUE(testRenderedString(strategy, str, tprop, "renderedString2.png"));

  tprop.setRotationDegreesCW(300);
  tprop.setRed(255);
  tprop.setBlue(255);
  tprop.setAlpha(127);
  tprop.setVAlign(TextProperties::VBottom);
  tprop.setHAlign(TextProperties::HRight);
  tprop.setFontStyles(TextProperties::Underline);

  EXPECT_TRUE(testRenderedString(strategy, str, tprop, "renderedString3.png"));
}

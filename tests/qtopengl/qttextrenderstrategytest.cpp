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

#include "qtopengltests.h"
#include <avogadro/qtopengl/qttextrenderstrategy.h>

#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/vector.h>

#include <QtGui/QImage>
#include <QtWidgets/QApplication>

#include <QtCore/QDebug>

#include <string>

typedef Avogadro::QtOpenGL::QtTextRenderStrategy Strategy;
typedef Avogadro::Rendering::TextRenderStrategy Interface;
using Avogadro::Rendering::TextProperties;
using Avogadro::Vector2i;

// Need to start an app to load fonts
#define START_QAPP                                                             \
  int argc = 1;                                                                \
  char argName[] = "FakeApp.exe";                                              \
  char* argv[2] = { argName, nullptr };                                        \
  QApplication app(argc, argv);                                                \
  Q_UNUSED(app)

namespace {

bool newInstance()
{
  bool result = true;
  Strategy orig;
  Interface* clone = orig.newInstance();
  if (dynamic_cast<Strategy*>(clone) == nullptr)
    result = false;
  delete clone;
  return result;
}

bool boundingBox()
{
  bool result = true;
  START_QAPP;

  Strategy strategy;
  TextProperties tprop;
  std::string testString("Testing string\nwith newlines!");
  tprop.setFontFamily(TextProperties::SansSerif);
  tprop.setPixelHeight(27);
  tprop.setHAlign(TextProperties::HCenter);
  tprop.setVAlign(TextProperties::VCenter);

  int bbox[4];
  // Valid sizes:
  int refbbox_1[4] = { -86, 85, -28, 27 };
  int refbbox_2[4] = { -69, 68, -27, 26 };
  strategy.boundingBox(testString, tprop, bbox);
  if (!std::equal(bbox, bbox + 4, refbbox_1) &&
      !std::equal(bbox, bbox + 4, refbbox_2)) {
    qCritical() << "boundingBox() failed: " << bbox[0] << bbox[1] << bbox[2]
                << bbox[3];
    result = false;
  }

  return result;
}

// Helpers for rendering tests:
bool compareComponents(unsigned char a, unsigned char b)
{
  // Allow small differences in component values.
  return std::abs(a - b) <= 2;
}

float validateBaseline(unsigned char* buffer, size_t numPixels,
                       const std::string& fileName)
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

bool testRenderedString(Strategy& strategy, const std::string& str,
                        const TextProperties& tprop,
                        const std::string& refFilename)
{
  int bbox[4];
  strategy.boundingBox(str, tprop, bbox);
  const Vector2i dims(bbox[1] - bbox[0] + 1, bbox[3] - bbox[2] + 1);
  std::vector<unsigned char> buffer(dims[0] * dims[1] * 4);
  if (buffer.empty())
    return false;
  strategy.render(str, tprop, &buffer[0], dims);
  return validateBaseline(&buffer[0], dims[0] * dims[1], refFilename);
}

// Useful for making new baselines:
void saveRenderedString(Strategy& strategy, const std::string& str,
                        const TextProperties& tprop,
                        const std::string& filename)
{
  int bbox[4];
  strategy.boundingBox(str, tprop, bbox);
  const Vector2i dims(bbox[1] - bbox[0] + 1, bbox[3] - bbox[2] + 1);
  std::vector<unsigned char> buffer(dims[0] * dims[1] * 4);
  if (buffer.empty())
    return;
  strategy.render(str, tprop, &buffer[0], dims);
  QImage img(&buffer[0], dims[0], dims[1], QImage::Format_ARGB32_Premultiplied);
  img.save(QString::fromStdString(filename));
}

bool render()
{
  bool result = true;
  START_QAPP;

  Strategy strategy;
  // Keep the buffer in a format that we can save with a QImage:
  strategy.setPreserveArgb(true);

  std::string str("Testing string\nwith newlines!\nSome lines are longer...");

  TextProperties tprop;
  tprop.setFontFamily(TextProperties::SansSerif);
  tprop.setPixelHeight(27);
  tprop.setColorRgb(63, 127, 255);
  tprop.setVAlign(TextProperties::VTop);
  tprop.setHAlign(TextProperties::HLeft);

  if (!testRenderedString(strategy, str, tprop, "renderedString1.png"))
    result = false;

  tprop.setRotationDegreesCW(25);
  tprop.setRed(255);
  tprop.setBlue(63);
  tprop.setAlpha(200);
  tprop.setVAlign(TextProperties::VCenter);
  tprop.setHAlign(TextProperties::HCenter);
  tprop.setItalic(true);
  tprop.setBold(true);

  if (!testRenderedString(strategy, str, tprop, "renderedString2.png"))
    result = false;

  tprop.setRotationDegreesCW(300);
  tprop.setRed(255);
  tprop.setBlue(255);
  tprop.setAlpha(127);
  tprop.setVAlign(TextProperties::VBottom);
  tprop.setHAlign(TextProperties::HRight);
  tprop.setFontStyles(TextProperties::Underline);

  if (!testRenderedString(strategy, str, tprop, "renderedString3.png"))
    result = false;

  return result;
}

} // end anon namespace

// Driver function:
int qttextrenderstrategytest(int, char** const)
{
  bool result = true;
  if (!newInstance())
    result = false;
  if (!boundingBox())
    result = false;
  if (!render())
    result = false;

  return result ? EXIT_SUCCESS : EXIT_FAILURE;
}

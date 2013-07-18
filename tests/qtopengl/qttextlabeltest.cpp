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

#include <avogadro/rendering/textlabel.h>

#include <utilities/vtktesting/imageregressiontest.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/absolutequadstrategy.h>
#include <avogadro/rendering/billboardquadstrategy.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/overlayquadstrategy.h>
#include <avogadro/rendering/textlabel.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/vector.h>

#include <QtOpenGL/QGLFormat>

#include <QtGui/QApplication>
#include <QtGui/QImage>

#include <QtCore/QTimer>

#include <iostream>

using Avogadro::Vector2f;
using Avogadro::Vector3f;
using Avogadro::Rendering::AbsoluteQuadStrategy;
using Avogadro::Rendering::BillboardQuadStrategy;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::OverlayQuadStrategy;
using Avogadro::Rendering::TextLabel;
using Avogadro::Rendering::TextProperties;

int qttextlabeltest(int argc, char *argv[])
{
  // Set up the default format for our GL contexts.
  QGLFormat defaultFormat = QGLFormat::defaultFormat();
  defaultFormat.setSampleBuffers(true);
  QGLFormat::setDefaultFormat(defaultFormat);

  QApplication app(argc, argv);
  Avogadro::QtOpenGL::GLWidget widget;
  widget.setGeometry(10, 10, 250, 250);
  widget.show();

  GeometryNode *geometry = new GeometryNode;
  widget.renderer().scene().rootNode().addChild(geometry);

  // Default text property:
  TextProperties tprop;

  // Test absolute positioning:
  AbsoluteQuadStrategy *absQuad = new AbsoluteQuadStrategy;
  absQuad->setAnchor(Vector3f(1.f, 1.f, 1.f));
  absQuad->setNormal(Vector3f(0.f, 1.f, 0.f));
  absQuad->setUp(Vector3f(0.f, 0.f, -1.f));
  absQuad->setHAlign(AbsoluteQuadStrategy::HCenter);
  absQuad->setVAlign(AbsoluteQuadStrategy::VCenter);

  tprop.setFontFamily(TextProperties::SansSerif);
  tprop.setHAlign(TextProperties::HCenter);
  tprop.setVAlign(TextProperties::VCenter);
  tprop.setPointSize(30);
  tprop.setUnderline(true);
  tprop.setColorRgba(0, 0, 255, 255);

  TextLabel *label = new TextLabel;
  label->setString("Test\nAbsolute Position");
  label->setTextProperties(tprop);
  label->setRenderPass(Avogadro::Rendering::TranslucentPass);
  label->setQuadPlacementStrategy(absQuad);
  geometry->addDrawable(label);

  // Test billboarding
  BillboardQuadStrategy *bboardQuad = new BillboardQuadStrategy;
  bboardQuad->setAnchor(Vector3f(1.f, 0.f, -2.f));
  bboardQuad->setRadius(2.5);
  bboardQuad->setHAlign(AbsoluteQuadStrategy::HRight);
  bboardQuad->setVAlign(AbsoluteQuadStrategy::VTop);

  tprop.setFontFamily(TextProperties::Mono);
  tprop.setHAlign(TextProperties::HRight);
  tprop.setVAlign(TextProperties::VTop);
  tprop.setUnderline(false);
  tprop.setItalic(true);
  tprop.setPointSize(20);
  tprop.setColorRgba(255, 0, 0, 200);

  label = new TextLabel;
  label->setString("Test\nBillboard\nPosition");
  label->setTextProperties(tprop);
  label->setRenderPass(Avogadro::Rendering::TranslucentPass);
  label->setQuadPlacementStrategy(bboardQuad);
  geometry->addDrawable(label);

  // Test overlay
  OverlayQuadStrategy *overQuad = new OverlayQuadStrategy;
  overQuad->setAnchor(Vector2f(0.05f, 0.05f));
  overQuad->setHAlign(AbsoluteQuadStrategy::HLeft);
  overQuad->setVAlign(AbsoluteQuadStrategy::VBottom);

  tprop.setFontFamily(TextProperties::Mono);
  tprop.setHAlign(TextProperties::HLeft);
  tprop.setVAlign(TextProperties::VBottom);
  tprop.setPointSize(8);
  tprop.setColorRgba(64, 255, 128, 128);
  tprop.setItalic(false);
  tprop.setBold(true);
  tprop.setRotationDegreesCW(12.3f);

  label = new TextLabel;
  label->setString("Test\nOverlay\nPosition");
  label->setTextProperties(tprop);
  label->setRenderPass(Avogadro::Rendering::OverlayPass);
  label->setQuadPlacementStrategy(overQuad);
  geometry->addDrawable(label);

  // Camera setup
  widget.renderer().camera().setIdentity();
  widget.renderer().camera().lookAt(Vector3f(1.f, 1.f, 0.f),
                                    Vector3f(-1.f, 0.f, -1.f),
                                    Vector3f(0.f, 0.f, -1.f));
  widget.renderer().camera().preTranslate(Vector3f(0.f, 0.f, -10.f));

  // Make sure the widget renders the scene, and store it in a QImage.
  widget.raise();
  widget.repaint();

  // Run the application for a while, and then quit so we can save an image.
  QTimer timer;
  timer.setSingleShot(true);
  app.connect(&timer, SIGNAL(timeout()), SLOT(quit()));
  timer.start(200);
  app.exec();

  // Grab the frame buffer of the GLWidget and save it to a QImage.
  QImage image = widget.grabFrameBuffer(false);

  // Set up the image regression test.
  Avogadro::VtkTesting::ImageRegressionTest test(argc, argv);

  // Do the image threshold test, printing output to the std::cout for ctest.
  return test.imageThresholdTest(image, std::cout);
}

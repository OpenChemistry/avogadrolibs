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

#include <utilities/vtktesting/imageregressiontest.h>

#include <avogadro/qtopengl/glwidget.h>

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/rendering/textlabel2d.h>
#include <avogadro/rendering/textlabel3d.h>
#include <avogadro/rendering/textproperties.h>

#include <avogadro/core/vector.h>

#include <QtOpenGL/QGLFormat>

#include <QtWidgets/QApplication>
#include <QtGui/QImage>

#include <QtCore/QTimer>

#include <iostream>

using Avogadro::Vector2f;
using Avogadro::Vector3f;
using Avogadro::Vector2i;
using Avogadro::Vector3ub;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::TextLabel2D;
using Avogadro::Rendering::TextLabel3D;
using Avogadro::Rendering::TextProperties;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::VtkTesting::ImageRegressionTest;

int qttextlabeltest(int argc, char *argv[])
{
  // Set up the default format for our GL contexts.
  QGLFormat defaultFormat = QGLFormat::defaultFormat();
  defaultFormat.setSampleBuffers(true);
  QGLFormat::setDefaultFormat(defaultFormat);

  // Create and show widget
  QApplication app(argc, argv);
  GLWidget widget;
  widget.setGeometry(10, 10, 500, 500);
  widget.show();

  // Create scene
  GeometryNode *geometry = new GeometryNode;
  widget.renderer().scene().rootNode().addChild(geometry);

  // Add a small sphere at the origin for reference:
  SphereGeometry *spheres = new SphereGeometry;
  spheres->addSphere(Vector3f::Zero(), Vector3ub(128, 128, 128), 0.1f);
  geometry->addDrawable(spheres);

  // Default text property:
  TextProperties tprop;

  // Test alignment:
  TextLabel3D *l3 = NULL;
  TextLabel2D *l2 = NULL;

  // 3D:
  tprop.setColorRgb(255, 0, 0);
  tprop.setAlign(TextProperties::HLeft, TextProperties::VTop);
  l3 = new TextLabel3D;
  l3->setText("Upper Left Anchor");
  l3->setAnchor(Vector3f::Zero());
  l3->setTextProperties(tprop);
  geometry->addDrawable(l3);

  tprop.setColorRgb(0, 255, 0);
  tprop.setAlign(TextProperties::HLeft, TextProperties::VBottom);
  l3 = new TextLabel3D;
  l3->setText("Bottom Left Anchor");
  l3->setAnchor(Vector3f::Zero());
  l3->setTextProperties(tprop);
  geometry->addDrawable(l3);

  tprop.setColorRgb(0, 0, 255);
  tprop.setAlign(TextProperties::HRight, TextProperties::VTop);
  l3 = new TextLabel3D;
  l3->setText("Upper Right Anchor");
  l3->setAnchor(Vector3f::Zero());
  l3->setTextProperties(tprop);
  geometry->addDrawable(l3);

  tprop.setColorRgb(255, 255, 0);
  tprop.setAlign(TextProperties::HRight, TextProperties::VBottom);
  l3 = new TextLabel3D;
  l3->setText("Bottom Right Anchor");
  l3->setAnchor(Vector3f::Zero());
  l3->setTextProperties(tprop);
  geometry->addDrawable(l3);

  tprop.setColorRgba(255, 255, 255, 220);
  tprop.setRotationDegreesCW(90.f);
  tprop.setAlign(TextProperties::HCenter, TextProperties::VCenter);
  l3 = new TextLabel3D;
  l3->setText("Centered Anchor (3D)");
  l3->setAnchor(Vector3f::Zero());
  l3->setTextProperties(tprop);
  l3->setRenderPass(Avogadro::Rendering::TranslucentPass);
  geometry->addDrawable(l3);
  tprop.setRotationDegreesCW(0.f);
  tprop.setAlpha(255);

  // 2D:
  tprop.setColorRgb(255, 0, 0);
  tprop.setAlign(TextProperties::HLeft, TextProperties::VTop);
  l2 = new TextLabel2D;
  l2->setText("Upper Left Corner");
  l2->setAnchor(Vector2i(0, widget.height()));
  l2->setTextProperties(tprop);
  geometry->addDrawable(l2);

  tprop.setColorRgb(0, 255, 0);
  tprop.setAlign(TextProperties::HLeft, TextProperties::VBottom);
  l2 = new TextLabel2D;
  l2->setText("Bottom Left Corner");
  l2->setAnchor(Vector2i(0, 0));
  l2->setTextProperties(tprop);
  geometry->addDrawable(l2);

  tprop.setColorRgb(0, 0, 255);
  tprop.setAlign(TextProperties::HRight, TextProperties::VTop);
  l2 = new TextLabel2D;
  l2->setText("Upper Right Corner");
  l2->setAnchor(Vector2i(widget.width(), widget.height()));
  l2->setTextProperties(tprop);
  geometry->addDrawable(l2);

  tprop.setColorRgb(255, 255, 0);
  tprop.setAlign(TextProperties::HRight, TextProperties::VBottom);
  l2 = new TextLabel2D;
  l2->setText("Bottom Right Corner");
  l2->setAnchor(Vector2i(widget.width(), 0));
  l2->setTextProperties(tprop);
  geometry->addDrawable(l2);

  tprop.setColorRgba(255, 255, 255, 220);
  tprop.setAlign(TextProperties::HCenter, TextProperties::VCenter);
  l2 = new TextLabel2D;
  l2->setText("Centered Anchor (2D)");
  l2->setAnchor(Vector2i(widget.width() / 2, widget.height() / 2));
  l2->setTextProperties(tprop);
  geometry->addDrawable(l2);

  // Test the TextLabel3D's radius feature:
  spheres->addSphere(Vector3f(0.f, 6.f, 0.f), Vector3ub(255, 255, 255), 1.f);

  tprop.setColorRgba(255, 128, 64, 255);
  tprop.setRotationDegreesCW(90.f);
  l3 = new TextLabel3D;
  l3->setText("Clipped");
  l3->setAnchor(Vector3f(0.f, 6.f, 0.f));
  l3->setTextProperties(tprop);
  geometry->addDrawable(l3);

  tprop.setColorRgba(64, 128, 255, 255);
  tprop.setRotationDegreesCW(45.f);
  l3 = new TextLabel3D;
  l3->setText("Projected");
  l3->setAnchor(Vector3f(0.f, 6.f, 0.f));
  l3->setTextProperties(tprop);
  l3->setRadius(1.f);
  geometry->addDrawable(l3);

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
  ImageRegressionTest test(argc, argv);

  // Do the image threshold test, printing output to the std::cout for ctest.
  return test.imageThresholdTest(image, std::cout);
}

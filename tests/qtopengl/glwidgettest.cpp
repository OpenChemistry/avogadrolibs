/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012-2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <avogadro/qtopengl/glwidget.h>
#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <utilities/vtktesting/imageregressiontest.h>

#include <QtCore/QTimer>
#include <QtGui/QImage>
#include <QtWidgets/QApplication>

#include <QtGui/QOpenGLContext>
#include <QtGui/QSurfaceFormat>

#include <iostream>

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereGeometry;
using Avogadro::QtOpenGL::GLWidget;
using Avogadro::VtkTesting::ImageRegressionTest;

int glwidgettest(int argc, char* argv[])
{
  // Set up the default format for our GL contexts.
  QSurfaceFormat defaultFormat = QSurfaceFormat::defaultFormat();
  defaultFormat.setSamples(4);
  QSurfaceFormat::setDefaultFormat(defaultFormat);

  QApplication app(argc, argv);
  GLWidget widget;
  widget.setGeometry(10, 10, 250, 250);
  widget.show();

  GeometryNode* geometry = new GeometryNode;
  SphereGeometry* spheres = new SphereGeometry;
  geometry->addDrawable(spheres);
  spheres->addSphere(Vector3f(0, 0, 0), Vector3ub(255, 0, 0), 0.5);
  spheres->addSphere(Vector3f(2, 0, 0), Vector3ub(0, 255, 0), 1.5);
  spheres->addSphere(Vector3f(0, 2, 1), Vector3ub(0, 0, 255), 1.0);
  widget.renderer().scene().rootNode().addChild(geometry);

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
  QImage image = widget.grabFramebuffer();

  // Set up the image regression test.
  ImageRegressionTest test(argc, argv);

  // Do the image threshold test, printing output to the std::cout for ctest.
  return test.imageThresholdTest(image, std::cout);
}

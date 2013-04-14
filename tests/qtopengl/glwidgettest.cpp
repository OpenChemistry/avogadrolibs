/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <avogadro/rendering/geometrynode.h>
#include <avogadro/rendering/spheregeometry.h>
#include <avogadro/qtopengl/glwidget.h>

#include <QtCore/QTimer>
#include <QtGui/QApplication>
#include <QtGui/QImage>
#include <QtGui/QPixmap>
#include <QtCore/QDebug>

#include <QtOpenGL/QGLFormat>

#include <vtkQImageToImageSource.h>
#include <vtkImageDifference.h>
#include <vtkImageShiftScale.h>
#include <vtkPNGReader.h>
#include <vtkPNGWriter.h>
#include <vtkImageData.h>
#include <vtkPointData.h>
#include <vtkUnsignedCharArray.h>
#include <vtkTrivialProducer.h>
#include <vtkNew.h>

#include <iostream>
#include <fstream>

using std::cout;
using std::endl;
using std::ifstream;
using std::ofstream;
using std::string;

using Avogadro::Vector3f;
using Avogadro::Vector3ub;
using Avogadro::Rendering::GeometryNode;
using Avogadro::Rendering::SphereGeometry;

double imageThresholdTest(const std::string &name, vtkImageData *imageData,
                          double threshold, std::ostream &os,
                          int argc, char *argv[])
{
  string baselineDir;
  string tempDir;
  for (int i = 0; i < argc; ++i) {
    string arg(argv[i]);
    if (arg == "--baseline" && i + 1 < argc)
      baselineDir = argv[++i];
    else if (arg == "--temporary" && i + 1 < argc)
      tempDir = argv[++i];
  }

  // Debug, should be removed once this works reliably on all platforms.
  cout << "baseline=" << baselineDir << " and temporary=" << tempDir << endl;

  // Check the input file exists, and can be read.
  string inputFileName(baselineDir + "/" + name + ".png");
  ifstream inputFile(inputFileName.c_str());
  if (inputFile.good()) {
    inputFile.close();
  }
  else {
    // There was no input file, write one to the temporary directory and return.
    os << "<DartMeasurement name=\"ImageNotFound\" type=\"test/string\">"
       << inputFileName << "</DartMeasurement>";
    vtkNew<vtkPNGWriter> pngWriter;
    pngWriter->SetFileName(string(tempDir + "/" + name + ".png").c_str());
    pngWriter->SetInputData(imageData);
    pngWriter->Update();
    pngWriter->Write();
    return 1000.0;
  }

  // Read in the baseline file.
  vtkNew<vtkPNGReader> pngReader;
  pngReader->SetFileName(inputFileName.c_str());

  vtkNew<vtkTrivialProducer> producer;
  producer->SetOutput(imageData);
  vtkNew<vtkImageDifference> imageDiff;
  imageDiff->SetInputConnection(producer->GetOutputPort());
  imageDiff->SetImageConnection(pngReader->GetOutputPort());

  double minError = VTK_DOUBLE_MAX;
  imageDiff->Update();
  minError = imageDiff->GetThresholdedError();

  if (minError > threshold) {
    vtkNew<vtkPNGWriter> pngWriter;
    pngWriter->SetFileName(string(tempDir + "/" + name + ".png").c_str());
    pngWriter->SetInputData(imageData);
    pngWriter->Write();
  }

  // TODO: Compare multiple base line images, then set errorIndex to the lowest
  // image difference index.
  int errorIndex = -1;

  // Output some information about the result for the dashboard.
  os << "<DartMeasurement name=\"ImageError\" type=\"numeric/double\">"
     << minError << "</DartMeasurement>" << endl;
  if (errorIndex <= 0) {
    os << "<DartMeasurement name=\"BaselineImage\" type=\"text/string\">"
       << "Standard</DartMeasurement>";
  }
  else {
    os << "<DartMeasurement name=\"BaselineImage\" type=\"numeric/integer\">"
       << errorIndex << "</DartMeasurement>";
  }

  if (minError <= threshold)
    return minError;

  // If we got this far the image test failed, and we need to do some more work.
  os << "Failed Image Test : " << minError << endl;

  // Let's try to write out a difference image.
  string diffFileName = tempDir + "/" + name + ".diff.png";
  ofstream diffFile(diffFileName.c_str());
  if (diffFile.good()) {
    diffFile.close();
    vtkNew<vtkImageShiftScale> imageDiffGamma;
    imageDiffGamma->SetInputConnection(imageDiff->GetOutputPort());
    imageDiffGamma->SetShift(0);
    imageDiffGamma->SetScale(10);
    // Now write it out.
    vtkNew<vtkPNGWriter> pngWriter;
    pngWriter->SetFileName(diffFileName.c_str());
    pngWriter->SetInputConnection(imageDiffGamma->GetOutputPort());
    pngWriter->Write();
    // Now write out the image that was produced.
    string testFileName = tempDir + "/" + name + ".png";
    pngWriter->SetFileName(testFileName.c_str());
    pngWriter->SetInputData(imageData);
    pngWriter->Write();
    // Now tell CDash all about it.
    os << "<DartMeasurementFile name=\"TestImage\" type=\"image/png\">"
       << testFileName << "</DartMeasurementFile>";
    os << "<DartMeasurementFile name=\"DifferenceImage\" type=\"image/png\">"
       << diffFileName << "</DartMeasurementFile>";
    os << "<DartMeasurementFile name=\"ValidImage\" type=\"image/png\">"
       << inputFileName << "</DartMeasurementFile>";
  }

  return minError;
}

int main(int argc, char *argv[])
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
  SphereGeometry *spheres = new SphereGeometry;
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
  QImage image = widget.grabFrameBuffer(false);

  // Now to convert this to a vtkImageData, so that we can diff it.
  vtkNew<vtkQImageToImageSource> qimage;
  qimage->SetQImage(&image);

  // Let's copy the image and remove the alpha channel as we don't use it.
  vtkNew<vtkImageData> imageData;
  qimage->Update();
  imageData->SetDimensions(qimage->GetOutput()->GetDimensions());
  imageData->AllocateScalars(VTK_UNSIGNED_CHAR, 3);
  unsigned char *source =
      reinterpret_cast<unsigned char*>(
        vtkUnsignedCharArray::SafeDownCast(qimage->GetOutput()
                                           ->GetPointData()->GetScalars())
                                           ->GetVoidPointer(0));
  unsigned char *dest =
      reinterpret_cast<unsigned char*>(
        vtkUnsignedCharArray::SafeDownCast(imageData->GetPointData()
                                           ->GetScalars())->GetVoidPointer(0));
  int size = image.width() * image.height();
  for (int i = 0; i < size; ++i) {
    dest[3 * i + 0] = source[4 * i + 0];
    dest[3 * i + 1] = source[4 * i + 1];
    dest[3 * i + 2] = source[4 * i + 2];
  }

  // Do the image threshold test.
  double threshold(15.0);
  double result = imageThresholdTest("glwidgettest", imageData.GetPointer(),
                                     threshold, std::cout, argc, argv);

  return result < threshold ? 0 : 1;
}

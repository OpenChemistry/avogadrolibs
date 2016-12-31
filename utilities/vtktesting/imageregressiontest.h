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

#ifndef AVOGADRO_UTILITIES_IMAGEREGRESSIONTEST_H
#define AVOGADRO_UTILITIES_IMAGEREGRESSIONTEST_H

#include <QtGui/QImage>

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
#include <string>

namespace Avogadro {
namespace VtkTesting {

/**
 * @class ImageRegressionTest imageregressiontest.h
 * <utilities/vtktesting/imageregressiontest.h>
 * @brief The ImageRegressionTest class provides utility functions to set up and
 * run image-based regression tests.
 * @author Marcus D. Hanwell
 *
 * The class is intended as a utility for image based regression tests, making
 * use of the VTK image filters for image diffing, and on failure enhancing the
 * differences and uploading them to CDash for review. It takes several standard
 * parameters on the command line, and can then accept a QImage or a
 * vtkImageData as input.
 *
 * In a typical driver script code of the following form would get an image of
 * the widget and compare it to a baseline image.
 @code
  // Grab the frame buffer of the GLWidget and save it to a QImage.
  QImage image = widget.grabFrameBuffer(false);

  // Set up the image regression test.
  Avogadro::VtkTesting::ImageRegressionTest test(argc, argv);

  // Do the image threshold test, printing output to the std::cout for ctest.
  return test.imageThresholdTest(image, std::cout);
 @endcode
 */

class ImageRegressionTest
{
public:
  /**
   * @brief Construct an ImageRegressionTest, processing command line arguments.
   * @param argc Number of arguments.
   * @param argv Array of command line arguments.
   *
   * The constructor is intended to process the command line arguments, taking
   * standard arguments and storing them in member variables. Expected arguments
   * are
   @code
   --baseline /path/to/baseline
   --temporary /path/to/tmp
   --name name-of-test
   --threshold 15
   * and storing them for later use. The first argument will be interpreted as
   * the test name if it does not start with --, it can also be overridden
   * later.
   */
  ImageRegressionTest(int argc, char *argv[]);

  /**
   * Set the baseline path, specifying the directory the baseline images are
   * located in.
   */
  void setBaselinePath(const std::string &path) { m_baselinePath = path; }

  /**
   * Get the path to the baseline directory.
   */
  std::string baselinePath() const { return m_baselinePath; }

  /**
   * Set the temporary path, specifying the directory temporary files can be
   * written.
   */
  void setTemporaryPath(const std::string &path) { m_temporaryPath = path; }

  /**
   * Get the path to the temporary directory.
   */
  std::string temporaryPath() const { return m_temporaryPath; }

  /**
   * Set the name of the test, this is used to compute baseline image names,
   * temporary files if the test fails etc.
   */
  void setName(const std::string &name_) { m_name = name_; }

  /**
   * Get the current name of the test.
   */
  std::string name() const { return m_name; }

  /**
   * Set the image threshold, this should normally be specified on the command
   * line using --threshold number.
   */
  void setThreshold(double threshold_) { m_threshold = threshold_; }

  /**
   * Get the specified image threshold.
   */
  double threshold() const { return m_threshold; }

  /**
   * Check if the image regression object is valid.
   */
  bool isValid() const { return m_valid; }

  /**
   * Perform an image threshold test, returning the measured image difference.
   */
  int imageThresholdTest(vtkImageData *imageData, std::ostream &os);

  /**
   * Perform an image threshold test, returning the measured image difference.
   */
  int imageThresholdTest(QImage &image, std::ostream &os);

  /**
   * Convert a QImage to a vtkImageData ready to be diffed.
   */
  void convertImage(QImage &inputImage, vtkImageData *outputImage);

private:
  std::string m_baselinePath;
  std::string m_temporaryPath;
  std::string m_name;
  double m_threshold;

  bool m_valid;

};

inline ImageRegressionTest::ImageRegressionTest(int argc, char *argv[])
  : m_threshold(15.0), m_valid(false)
{
  if (argc < 2) {
    m_valid = false;
  }

  for (int i = 0; i < argc; ++i) {
    std::string arg(argv[i]);
    if (i == 0 && arg[0] != '-' && arg[1] != '-') {
      // It is the test name.
      m_name = argv[i];
      continue;
    }
    if (arg == "--baseline" && i + 1 < argc)
      m_baselinePath = argv[++i];
    else if (arg == "--temporary" && i + 1 < argc)
      m_temporaryPath = argv[++i];
    else if (arg == "--name" && i + 1 < argc)
      m_name = argv[++i];
    else if (arg == "--threshold" && i + 1 < argc)
      m_threshold = strtod(argv[++i], nullptr);
  }
  if (!m_baselinePath.empty() && !m_temporaryPath.empty() && !m_name.empty())
    m_valid = true;
}

inline int ImageRegressionTest::imageThresholdTest(vtkImageData *imageData,
                                                   std::ostream &os)
{
  // Check the input file exists, and can be read.
  std::string inputFileName(m_baselinePath + "/" + m_name + ".png");
  std::ifstream inputFile(inputFileName.c_str());
  if (inputFile.good()) {
    inputFile.close();
  }
  else {
    // There was no input file, write one to the temporary directory and return.
    std::string testFileName = m_temporaryPath + "/" + m_name + ".png";
    vtkNew<vtkPNGWriter> pngWriter;
    pngWriter->SetFileName(testFileName.c_str());
    pngWriter->SetInputData(imageData);
    pngWriter->Write();
    os << "<DartMeasurement name=\"ImageNotFound\" type=\"test/string\">"
       << inputFileName << "</DartMeasurement>" << std::endl;
    os << "<DartMeasurementFile name=\"TestImage\" type=\"image/png\">"
       << testFileName << "</DartMeasurementFile>" << std::endl;
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

  if (minError <= m_threshold)
    return minError;

  // If we got this far the image test failed, and we need to do some more work.
  os << "Failed Image Test : " << minError << endl;

  // Let's try to write out a difference image.
  std::string diffFileName = m_temporaryPath + "/" + m_name + ".diff.png";
  std::ofstream diffFile(diffFileName.c_str());
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
    std::string testFileName = m_temporaryPath + "/" + m_name + ".png";
    pngWriter->SetFileName(testFileName.c_str());
    pngWriter->SetInputData(imageData);
    pngWriter->Write();
    // Now tell CDash all about it.
    os << "<DartMeasurementFile name=\"TestImage\" type=\"image/png\">"
       << testFileName << "</DartMeasurementFile>" << std::endl;
    os << "<DartMeasurementFile name=\"DifferenceImage\" type=\"image/png\">"
       << diffFileName << "</DartMeasurementFile>" << std::endl;
    os << "<DartMeasurementFile name=\"ValidImage\" type=\"image/png\">"
       << inputFileName << "</DartMeasurementFile>" << std::endl;
  }

  return minError < m_threshold ? 0 : 1;
}

inline int ImageRegressionTest::imageThresholdTest(QImage &image,
                                                   std::ostream &os)
{
  vtkNew<vtkImageData> imageData;
  convertImage(image, imageData.GetPointer());
  return imageThresholdTest(imageData.GetPointer(), os);
}

inline void ImageRegressionTest::convertImage(QImage &inputImage,
                                              vtkImageData *outputImage)
{
  // Now to convert this to a vtkImageData, so that we can diff it.
  vtkNew<vtkQImageToImageSource> qimage;
  qimage->SetQImage(&inputImage);

  // Let's copy the image and remove the alpha channel as we don't use it.
  qimage->Update();
  outputImage->SetDimensions(qimage->GetOutput()->GetDimensions());
  outputImage->AllocateScalars(VTK_UNSIGNED_CHAR, 3);
  unsigned char *source =
      reinterpret_cast<unsigned char*>(
        vtkUnsignedCharArray::SafeDownCast(qimage->GetOutput()
                                           ->GetPointData()->GetScalars())
                                           ->GetVoidPointer(0));
  unsigned char *dest =
      reinterpret_cast<unsigned char*>(
        vtkUnsignedCharArray::SafeDownCast(outputImage->GetPointData()
                                           ->GetScalars())->GetVoidPointer(0));
  int size = inputImage.width() * inputImage.height();
  for (int i = 0; i < size; ++i) {
    dest[3 * i + 0] = source[4 * i + 0];
    dest[3 * i + 1] = source[4 * i + 1];
    dest[3 * i + 2] = source[4 * i + 2];
  }
}

}
}

#endif // AVOGADRO_UTILITIES_IMAGEREGRESSIONTEST_H

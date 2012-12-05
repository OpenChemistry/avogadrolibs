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

#include <avogadro/qtopengl/glwidget.h>

#include <QtGui/QApplication>
#include <QtGui/QImage>
#include <QtGui/QPixmap>
#include <QtCore/QDebug>

#include <vtkQImageToImageSource.h>
#include <vtkImageDifference.h>
#include <vtkPNGReader.h>
#include <vtkImageData.h>
#include <vtkPointData.h>
#include <vtkUnsignedCharArray.h>
#include <vtkTrivialProducer.h>
#include <vtkNew.h>

#include <iostream>

int main(int argc, char *argv[])
{
  QApplication app(argc, argv);
  Avogadro::QtOpenGL::GLWidget widget;
  QPixmap pixmap = widget.renderPixmap(200, 200, false);
  pixmap.save("glwidgettest.png", 0, 100);

  QImage image = pixmap.toImage();

  vtkNew<vtkImageDifference> imageDiff;
  vtkNew<vtkQImageToImageSource> qimage;
  qimage->SetQImage(&image);
  vtkNew<vtkPNGReader> pngReader;
  pngReader->SetFileName("glwidgettest.png");

  // Let's copy the image and remove the alpha channel we don't use.
  vtkNew<vtkImageData> imageData;
  qimage->Update();
  imageData->SetDimensions(qimage->GetOutput()->GetDimensions());
  imageData->AllocateScalars(VTK_UNSIGNED_CHAR, 3);
  unsigned char *source =
      reinterpret_cast<unsigned char*>(vtkUnsignedCharArray::SafeDownCast(qimage->GetOutput()->GetPointData()->GetScalars())->GetVoidPointer(0));
  unsigned char *dest =
      reinterpret_cast<unsigned char*>(vtkUnsignedCharArray::SafeDownCast(imageData->GetPointData()->GetScalars())->GetVoidPointer(0));
  int size = image.width() * image.height();
  for (int i = 0; i < size; ++i) {
    dest[3 * i + 0] = source[4 * i + 0];
    dest[3 * i + 1] = source[4 * i + 1];
    dest[3 * i + 2] = source[4 * i + 2];
  }
  vtkNew<vtkTrivialProducer> producer;
  producer->SetOutput(imageData.GetPointer());
  imageDiff->SetInputConnection(producer->GetOutputPort());
  imageDiff->SetImageConnection(pngReader->GetOutputPort());

  double minError = VTK_DOUBLE_MAX;
  imageDiff->Update();
  minError = imageDiff->GetThresholdedError();

  qDebug() << "Image error measured to be: " << minError;

  return minError < 15 ? 0 : 1;
}

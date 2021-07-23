/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2021 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_VTK_QVTKOPENGLWIDGET_H
#define AVOGADRO_VTK_QVTKOPENGLWIDGET_H

#include <vtkVersionMacros.h>

#if VTK_MAJOR_VERSION >= 9
#define AVOGADRO_QVTKOPENGLWIDGET QVTKOpenGLStereoWidget
#define AVOGADRO_SETENABLEHIDPI_OVERRIDE
#include <QVTKOpenGLStereoWidget.h>
#else
#define AVOGADRO_QVTKOPENGLWIDGET QVTKOpenGLWidget
#define AVOGADRO_SETENABLEHIDPI_OVERRIDE override
#include <QVTKOpenGLWidget.h>
#endif

namespace Avogadro {
using QVTKOpenGLWidget = ::AVOGADRO_QVTKOPENGLWIDGET;
} // namespace Avogadro

#endif // AVOGADRO_VTK_QVTKOPENGLWIDGET_H

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

#include "opendxreader.h"

#include <avogadro/core/cube.h>

#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QVector>

namespace Avogadro {
namespace QtPlugins {

using Core::Cube;

OpenDxReader::OpenDxReader() : m_cube(nullptr)
{
}

OpenDxReader::~OpenDxReader()
{
}

bool OpenDxReader::readFile(const QString& fileName)
{
  QFile file(fileName);
  if (!file.open(QFile::ReadOnly)) {
    m_errorString = "Failed to open file for reading";
    return false;
  }

  delete m_cube;

  Vector3i dim(0, 0, 0);
  Vector3 origin(0, 0, 0);
  QVector<Vector3> spacings;
  std::vector<double> values;

  while (!file.atEnd()) {
    QByteArray line = file.readLine();
    QTextStream stream(line);

    if (line.isEmpty()) {
      // skip empty line
      continue;
    } else if (line[0] == '#') {
      // skip comment line
      continue;
    } else if (line.startsWith("object")) {
      if (dim[0] != 0)
        continue;
      QString unused;
      stream >> unused >> unused >> unused >> unused >> unused;
      stream >> dim[0] >> dim[1] >> dim[2];
    } else if (line.startsWith("origin")) {
      QString unused;
      stream >> unused >> origin[0] >> origin[1] >> origin[2];
    } else if (line.startsWith("delta")) {
      QString unused;
      Vector3 delta;
      stream >> unused >> delta[0] >> delta[1] >> delta[2];
      spacings.append(delta);
    } else if (line.startsWith("attribute")) {
      continue;
    } else if (line.startsWith("component")) {
      continue;
    } else {
      // data line
      while (!stream.atEnd()) {
        double value;
        stream >> value;
        values.push_back(value);
        stream.skipWhiteSpace();
      }
    }
  }

  Vector3 spacing(spacings[0][0], spacings[1][1], spacings[2][2]);

  // create potential cube
  m_cube = new Cube;
  m_cube->setCubeType(Cube::ESP);
  m_cube->setLimits(origin, dim, spacing);
  m_cube->setData(values);

  return true;
}

QString OpenDxReader::errorString() const
{
  return m_errorString;
}

Cube* OpenDxReader::cube() const
{
  return m_cube;
}
}
}

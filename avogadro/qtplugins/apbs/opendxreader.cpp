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

#include <QDebug>
#include <QFile>

namespace Avogadro {
namespace QtPlugins {

OpenDxReader::OpenDxReader()
  : m_positivePotentialCube(0),
    m_negativePotentialCube(0)
{
}

OpenDxReader::~OpenDxReader()
{
}

bool OpenDxReader::readFile(const QString &fileName)
{
  QFile file(fileName);
  if (!file.open(QFile::ReadOnly)) {
    m_errorString = "Failed to open file for reading";
    return false;
  }

  delete m_positivePotentialCube;
  delete m_negativePotentialCube;

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
    }
    else if (line[0] == '#') {
      // skip comment line
      continue;
    }
    else if (line.startsWith("object")) {
      if (dim[0] != 0)
        continue;
      QString unused;
      stream >> unused >> unused >> unused >> unused >> unused;
      stream >> dim[0] >> dim[1] >> dim[2];
    }
    else if (line.startsWith("origin")) {
      QString unused;
      stream >> unused >> origin[0] >> origin[1] >> origin[2];
    }
    else if (line.startsWith("delta")) {
      QString unused;
      Vector3 delta;
      stream >> unused >> delta[0] >> delta[1] >> delta[2];
      spacings.append(delta);
    }
    else if (line.startsWith("attribute")) {
      continue;
    }
    else if (line.startsWith("component")) {
      continue;
    }
    else {
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

  // create positive cube
  m_positivePotentialCube = new QtGui::Cube();
  m_positivePotentialCube->setCubeType(QtGui::Cube::ESP);
  m_positivePotentialCube->setLimits(origin, dim, spacing);
  m_positivePotentialCube->setData(values);

  // create negative cube
  m_negativePotentialCube = new QtGui::Cube();
  m_negativePotentialCube->setCubeType(QtGui::Cube::ESP);
  m_negativePotentialCube->setLimits(origin, dim, spacing);
  m_negativePotentialCube->setData(values);

  return true;
}

QString OpenDxReader::errorString() const
{
  return m_errorString;
}

QtGui::Cube* OpenDxReader::positivePotentialCube() const
{
  return m_positivePotentialCube;
}

QtGui::Cube* OpenDxReader::negativePotentialCube() const
{
  return m_negativePotentialCube;
}

}
}

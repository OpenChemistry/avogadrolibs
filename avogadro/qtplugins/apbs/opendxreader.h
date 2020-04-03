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

#ifndef AVOGADRO_QTPLUGINS_APBS_OPENDXREADER_H
#define AVOGADRO_QTPLUGINS_APBS_OPENDXREADER_H

#include <QtCore/QString>

namespace Avogadro {

namespace Core {
class Cube;
}

namespace QtPlugins {

/**
 * @brief Provide a reader for OpenDX files.
 */
class OpenDxReader
{
public:
  /**
   * Constructor for OpenDxReader.
   */
  OpenDxReader();

  /**
   * Destructor for OpenDxReader.
   */
  ~OpenDxReader();

  /**
   * Reads the file with the given @fileName. Returns false if an error
   * occurs.
   */
  bool readFile(const QString& fileName);

  /**
   * @return String describing the last error that occurred.
   */
  QString errorString() const;

  /**
   * Returns the potential energy cube read from the file. Returns 0 if no file
   * has been successfully read.
   */
  Core::Cube* cube() const;

private:
  Core::Cube* m_cube;
  QString m_errorString;
};
}
}

#endif // AVOGADRO_QTPLUGINS_APBS_OPENDXREADER_H

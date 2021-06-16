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

#ifndef AVOGADRO_QTGUI_BACKGROUNDFILEFORMAT_H
#define AVOGADRO_QTGUI_BACKGROUNDFILEFORMAT_H

#include "avogadroqtguiexport.h"

#include <QtCore/QObject>
#include <QtCore/QString>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Io {
class FileFormat;
}

namespace QtGui {

/**
 * @brief The BackgroundFileFormat class provides a thin QObject wrapper around
 * an instance of Io::FileFormat.
 */
class AVOGADROQTGUI_EXPORT BackgroundFileFormat : public QObject
{
  Q_OBJECT
public:
  /**
   * This class takes ownership of @a format and will delete it when destructed.
   */
  explicit BackgroundFileFormat(Io::FileFormat* format,
                                QObject* aparent = nullptr);
  ~BackgroundFileFormat();

  /**
   * The molecule instance to read/write.
   * @{
   */
  void setMolecule(Core::Molecule* mol) { m_molecule = mol; }
  Core::Molecule* molecule() const { return m_molecule; }
  /**@}*/

  /**
   * The name of the file to read/write.
   * @{
   */
  void setFileName(const QString& filename) { m_fileName = filename; }
  QString fileName() const { return m_fileName; }
  /**@}*/

  /**
   * The Io::FileFormat to use.
   */
  Io::FileFormat* fileFormat() const { return m_format; }

  /**
   * @return True if the operation was successful.
   */
  bool success() const { return m_success; }

  /**
   * @return An error string, set if success() is false.
   */
  QString error() const { return m_error; }

signals:

  /**
   * Emitted when a call to read or write is called.
   */
  void finished();

public slots:

  /**
   * Use the fileFormat() to read fileName() into molecule().
   */
  void read();

  /**
   * Use the fileFormat() to write fileName() from molecule().
   */
  void write();

private:
  Io::FileFormat* m_format;
  Core::Molecule* m_molecule;
  QString m_fileName;
  QString m_error;
  bool m_success;
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_BACKGROUNDFILEFORMAT_H

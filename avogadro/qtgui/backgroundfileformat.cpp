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

#include "backgroundfileformat.h"

#include <avogadro/io/fileformat.h>

namespace Avogadro {

namespace QtGui {

BackgroundFileFormat::BackgroundFileFormat(Io::FileFormat* format,
                                           QObject* aparent)
  : QObject(aparent), m_format(format), m_molecule(nullptr), m_success(false)
{}

BackgroundFileFormat::~BackgroundFileFormat()
{
  delete m_format;
}

void BackgroundFileFormat::read()
{
  m_success = false;
  m_error.clear();

  if (!m_molecule)
    m_error = tr("No molecule set in BackgroundFileFormat!");

  if (!m_format)
    m_error = tr("No Io::FileFormat set in BackgroundFileFormat!");

  if (m_fileName.isEmpty())
    m_error = tr("No file name set in BackgroundFileFormat!");

  if (m_error.isEmpty()) {
    m_success =
      m_format->readFile(m_fileName.toLocal8Bit().data(), *m_molecule);

    if (!m_success)
      m_error = QString::fromStdString(m_format->error());
  }

  emit finished();
}

void BackgroundFileFormat::write()
{
  m_success = false;
  m_error.clear();

  if (!m_molecule)
    m_error = tr("No molecule set in BackgroundFileFormat!");

  if (!m_format)
    m_error = tr("No Io::FileFormat set in BackgroundFileFormat!");

  if (m_fileName.isEmpty())
    m_error = tr("No file name set in BackgroundFileFormat!");

  if (m_error.isEmpty()) {
    m_success =
      m_format->writeFile(m_fileName.toLocal8Bit().data(), *m_molecule);

    if (!m_success)
      m_error = QString::fromStdString(m_format->error());
  }

  emit finished();
}

} // namespace QtGui
} // namespace Avogadro

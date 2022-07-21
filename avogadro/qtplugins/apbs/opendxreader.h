/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
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

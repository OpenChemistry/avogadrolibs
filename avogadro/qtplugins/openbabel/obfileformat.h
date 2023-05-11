/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBFILEFORMAT_H
#define AVOGADRO_QTPLUGINS_OBFILEFORMAT_H

#include <avogadro/io/fileformat.h>

#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/io/pdbformat.h>

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The OBFileFormat class implements the FileFormat API for using an
 * OBProcess for file IO.
 */
class OBFileFormat : public Avogadro::Io::FileFormat
{
public:
  OBFileFormat(const std::string& name_, const std::string& identifier_,
               const std::string& description_,
               const std::string& specificationUrl_,
               const std::vector<std::string> fileExtensions_,
               const std::vector<std::string> mimeTypes_,
               const std::string& defaultFormat_,
               bool fileOnly_ = false);
  ~OBFileFormat() override;

  Operations supportedOperations() const override
  {
    return m_rwFlags | File | (m_fileOnly ? None : Stream | String);
  }

  bool read(std::istream& in, Core::Molecule& molecule) override;
  bool write(std::ostream& out, const Core::Molecule& molecule) override;

  void clear() override;

  FileFormat* newInstance() const override;

  std::string description() const override { return m_description; }
  std::string identifier() const override { return m_identifier; }
  std::string name() const override { return m_name; }
  std::string specificationUrl() const override { return m_specificationUrl; }

  std::vector<std::string> fileExtensions() const override
  {
    return m_fileExtensions;
  }
  std::vector<std::string> mimeTypes() const override { return m_mimeTypes; }

  /**
   * Set whether this format supports read and/or write operations.
   */
  void setReadWriteFlags(Operations ops) { m_rwFlags = ops & ReadWrite; }

  /** Whether or not the format supports files only. This is needed for
   * multifile formats. */
  void setFileOnly(bool f) { m_fileOnly = f; }
  bool fileOnly() const { return m_fileOnly; }
  /** @} */

  class ProcessListener;

private:
  Operations m_rwFlags;
  std::string m_description;
  std::vector<std::string> m_fileExtensions;
  std::vector<std::string> m_mimeTypes;
  std::string m_identifier;
  std::string m_name;
  std::string m_specificationUrl;
  std::string m_defaultFormat;
  bool m_fileOnly;

  // internal format objects for interchange with obabel
  Io::CjsonFormat m_cjsonFormat;
  Io::CmlFormat m_cmlFormat;
  Io::PdbFormat m_pdbFormat;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBFILEFORMAT_H

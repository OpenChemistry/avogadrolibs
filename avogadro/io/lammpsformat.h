/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_IO_LAMMPSFORMAT_H
#define AVOGADRO_IO_LAMMPSFORMAT_H

#include "fileformat.h"

namespace Avogadro {
namespace Io {

/**
 * @class LammpsTrajectoryFormat lammpsformat.h <avogadro/io/lammpsformat.h>
 * @brief Implementation of the generic lammps trajectory format.
 * @author Adarsh B
 */

class AVOGADROIO_EXPORT LammpsTrajectoryFormat : public FileFormat
{
public:
  LammpsTrajectoryFormat();
  ~LammpsTrajectoryFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override
  {
    return new LammpsTrajectoryFormat;
  }
  std::string identifier() const override
  {
    return "Avogadro: LAMMPS Trajectory dump";
  }
  std::string name() const override { return "LAMMPS"; }
  std::string description() const override
  {
    return "Generic LAMMPS Trajectory format.";
  }

  std::string specificationUrl() const override
  {
    return "http://lammps.sandia.gov/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& molecule) override;
  bool write(std::ostream& outStream, const Core::Molecule& molecule) override;
};

class AVOGADROIO_EXPORT LammpsDataFormat : public FileFormat
{
public:
  LammpsDataFormat();
  ~LammpsDataFormat() override;

  Operations supportedOperations() const override
  {
    return ReadWrite | MultiMolecule | File | Stream | String;
  }

  FileFormat* newInstance() const override { return new LammpsDataFormat; }
  std::string identifier() const override { return "Avogadro: LAMMPS Data"; }
  std::string name() const override { return "LAMMPS"; }
  std::string description() const override
  {
    return "Generic LAMMPS Data format.";
  }

  std::string specificationUrl() const override
  {
    return "http://lammps.sandia.gov/";
  }

  std::vector<std::string> fileExtensions() const override;
  std::vector<std::string> mimeTypes() const override;

  bool read(std::istream& inStream, Core::Molecule& molecule) override;
  bool write(std::ostream& outStream, const Core::Molecule& molecule) override;
};

} // end Io namespace
} // end Avogadro namespace

#endif // AVOGADRO_IO_LAMMPSFORMAT_H

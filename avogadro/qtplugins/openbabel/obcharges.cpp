/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obcharges.h"
#include "obprocess.h"

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

#include <nlohmann/json.hpp>

#include <QtCore/QDebug>

#include <algorithm>

namespace Avogadro {

using Core::Array;
using Core::Molecule;

namespace QtPlugins {

OBCharges::OBCharges(const std::string& id) : m_identifier(id)
{
  // set the element mask based on our type / identifier
  m_elements.reset();
  if (id == "eqeq") {
    // defined for 1-84
    for (unsigned int i = 1; i <= 84; ++i) {
      m_elements.set(i);
    }
  } else if (id == "eem") {
    // H, Li, B, C, N, O, F, Na, Mg, Si, P, S, Cl
    m_elements.set(1);
    m_elements.set(3);
    m_elements.set(5);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(11);
    m_elements.set(12);
    m_elements.set(14);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
  } else if (id == "eem2015ba") {
    // H, C, N, O, F, P, S, Cl, Br, I
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);
  } else if (id == "gasteiger") {
    // H, C, N, O, F, P, S, Cl, Br, I, Al
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(13);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);
  } else if (id == "mmff94") {
    // H, C, N, O, F, Si, P, S, Cl, Br, and I
    // ions - Fe, F, Cl, Br, Li, Na, K, Zn, Ca, Cu, Mg
    m_elements.set(1);
    m_elements.set(6);
    m_elements.set(7);
    m_elements.set(8);
    m_elements.set(9);
    m_elements.set(14);
    m_elements.set(15);
    m_elements.set(16);
    m_elements.set(17);
    m_elements.set(35);
    m_elements.set(53);

    // ions
    m_elements.set(3);
    m_elements.set(11);
    m_elements.set(12);
    m_elements.set(19);
    m_elements.set(20);
    m_elements.set(26);
    m_elements.set(29);
    m_elements.set(30);
  }
}

OBCharges::~OBCharges() {}

std::string OBCharges::name() const
{
  if (m_identifier == "eqeq")
    return "EQEq";
  else if (m_identifier == "eem")
    return "EEM";
  else if (m_identifier == "eem2015ba")
    return "EEM 2015";
  else if (m_identifier == "gasteiger")
    return "Gasteiger";
  else if (m_identifier == "mmff94")
    return "MMFF94";
  else
    return "";
}

MatrixX OBCharges::partialCharges(const Core::Molecule& molecule) const
{
  MatrixX charges(molecule.atomCount(), 1);

  if (m_identifier.empty()) {
    // no identifier, so we can't get the charges
    return charges;
  }
  if (molecule.atomCount() == 0)
    return charges; // nothing to run obabel on

  // check to see if we already have them in the molecule
  charges = molecule.partialCharges(m_identifier);
  // if the number of charges matches the number of atoms
  // and there's a non-zero charge, then we're done
  if (charges.rows() == static_cast<Eigen::Index>(molecule.atomCount())) {
    for (unsigned int i = 0; i < charges.rows(); ++i) {
      if (abs(charges(i, 0)) > 0.00001)
        return charges;
    }
  }

  // Otherwise run obabel. This is synchronous and is called from data() while
  // a view is painting, so it must not run the event loop (a nested paint of
  // the same window crashes): waitForFinished() blocks instead, and the
  // result arrives through this direct connection before it returns.
  OBProcess process;
  bool finished = false;
  Core::Array<double> output;
  QObject::connect(&process, &OBProcess::chargesFinished, &process,
                   [&finished, &output](const Core::Array<double>& result) {
                     output = result;
                     finished = true;
                   });

  std::string outputString;
  // todo - check for failure, append errors, etc.
  m_cmlFormat.writeString(outputString, molecule);

  process.calculateCharges(QByteArray(outputString.c_str()), "cml",
                           m_identifier);

  process.waitForFinished(120000);
  if (!finished) {
    qDebug() << "Charges timed out.";
    return charges;
  }

  // Push the output into our charges array. obabel may report a different
  // number of atoms than we sent, so never write past the molecule's.
  const auto atomCount = static_cast<Eigen::Index>(molecule.atomCount());
  charges = MatrixX::Zero(atomCount, 1);
  const auto count =
    std::min(static_cast<Eigen::Index>(output.size()), atomCount);
  for (Eigen::Index i = 0; i < count; ++i)
    charges(i, 0) = output[static_cast<size_t>(i)];

  // Mark an all-zero result as computed, or the check above would run obabel
  // again on every request.
  if (atomCount > 0 && abs(charges(0, 0)) < 0.00001)
    charges(0, 0) = 0.0001;

  if (output.size() != molecule.atomCount())
    qDebug() << "Charges size mismatch.";
  return charges;
}

MatrixX OBCharges::partialCharges(Core::Molecule& molecule) const
{
  MatrixX charges =
    partialCharges(static_cast<const Core::Molecule&>(molecule));
  // cache the charges and allow them to show up in output
  molecule.setPartialCharges(m_identifier, charges);
  return charges;
}

} // namespace QtPlugins
} // namespace Avogadro

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "obcharges.h"
#include "obprocess.h"

#include <avogadro/core/array.h>
#include <avogadro/core/molecule.h>

#include <nlohmann/json.hpp>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QTimer>

namespace Avogadro {

using Core::Array;
using Core::Molecule;

namespace QtPlugins {

class OBCharges::ProcessListener : public QObject
{
  Q_OBJECT
public:
  ProcessListener() : QObject(), m_finished(false) {}

  bool waitForOutput(Array<double>& output, int msTimeout = 120000)
  {
    if (!wait(msTimeout))
      return false;

    // success!
    output = m_output;
    return true;
  }

public slots:
  void responseReceived(const Array<double> output)
  {
    m_finished = true;
    m_output = output;
  }

private:
  bool wait(int msTimeout)
  {
    QTimer timer;
    timer.start(msTimeout);

    while (timer.isActive() && !m_finished)
      qApp->processEvents(QEventLoop::AllEvents, 500);

    return m_finished;
  }

  // OBProcess* m_process;
  bool m_finished;
  Array<double> m_output;
};

OBCharges::OBCharges(const std::string& id) : m_identifier(id), ChargeModel()
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

MatrixX OBCharges::partialCharges(Core::Molecule& molecule) const
{
  // get the charges from obabel
  MatrixX charges(molecule.atomCount(), 1);

  if (m_identifier.empty()) {
    // no identifier, so we can't get the charges
    return charges;
  }

  // check to see if we already have them in the molecule
  charges = molecule.partialCharges(m_identifier);
  // if there's a non-zero charge, then we're done
  for (unsigned int i = 0; i < charges.rows(); ++i) {
    if (abs(charges(i, 0)) > 0.00001)
      return charges;
  }

  // otherwise, we're going to run obprocess to get the charges
  OBProcess process;
  ProcessListener listener;
  QObject::connect(&process, &OBProcess::chargesFinished, &listener,
                   &ProcessListener::responseReceived);

  std::string outputString;
  // todo - check for failure, append errors, etc.
  m_cmlFormat.writeString(outputString, molecule);

  process.calculateCharges(QByteArray(outputString.c_str()), "cml",
                           m_identifier);

  Core::Array<double> output;
  if (!listener.waitForOutput(output)) {
    qDebug() << "Charges timed out.";
    return charges;
  }

  // push the output into our charges array
  for (unsigned int i = 0; i < output.size(); ++i) {
    charges(i, 0) = output[i];
  }

  // workaround failed runs causing the code to freeze
  if (abs(charges(0, 0)) < 0.00001)
    charges(0, 0) = 0.0001;

  // cache the charges and allow them to show up in output
  molecule.setPartialCharges(m_identifier, charges);
  return charges;
}

} // namespace QtPlugins
} // namespace Avogadro

#include "obcharges.moc"

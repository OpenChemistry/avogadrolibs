/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_OBCHARGES_H
#define AVOGADRO_QTPLUGINS_OBCHARGES_H

#include <avogadro/calc/chargemodel.h>
#include <avogadro/io/cmlformat.h>

namespace Avogadro {
namespace QtPlugins {

class OBCharges : public Avogadro::Calc::ChargeModel
{
public:
  OBCharges(const std::string& identifier = "");
  virtual ~OBCharges();

  /**
   * Create a new instance of the file format class. Ownership passes to the
   * caller.
   */
  virtual OBCharges* newInstance() const override { return new OBCharges; }

  /**
   * @brief A unique identifier defined by the file
   */
  virtual std::string identifier() const override { return m_identifier; }

  /**
   * @brief Set the identifier
   */
  virtual void setIdentifier(const std::string& identifier)
  {
    m_identifier = identifier;
  }

  /**
   * @brief Based on the identifiers -- for the menus, etc.
   */
  virtual std::string name() const override;

  /**
   * @brief The element mask for a particular OB charge model (e.g., Gasteiger)
   * @return the mask relevant for this method
   */
  virtual Core::Molecule::ElementMask elements() const override
  {
    return m_elements;
  }

  /**
   * @brief Retrieve the relevant charges from the molecule for our defined type
   */
  virtual MatrixX partialCharges(Core::Molecule& mol) const override;

  /**
   * @brief Synchronous use of the OBProcess.
   */
  class ProcessListener;

protected:
  std::string m_identifier;
  std::string m_name;
  Core::Molecule::ElementMask m_elements;

  mutable Io::CmlFormat m_cmlFormat;
};

} // namespace QtPlugins
} // namespace Avogadro

#endif // AVOGADRO_QTPLUGINS_OBCHARGES_H

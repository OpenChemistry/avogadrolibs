/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_CALC_DEFAULTMODEL_H
#define AVOGADRO_CALC_DEFAULTMODEL_H

#include "avogadrocalcexport.h"

#include <avogadro/calc/chargemodel.h>

namespace Avogadro {

namespace Core {
class Molecule;
}

namespace Calc {

/**
 * @class DefaultModel defaultmodel.h <avogadro/calc/defaultmodel.h>
 * @brief Default charge model for file-provided atomic charges
 * @author Geoffrey R. Hutchison
 *
 * This is a default model for using atomic partial charges from a
 * file (e.g., quantum chemistry packages often provide Mulliken charges)
 *
 * The class
 */

class AVOGADROCALC_EXPORT DefaultModel : public ChargeModel
{
public:
  DefaultModel(const std::string& identifier = "");
  virtual ~DefaultModel();

  /**
   * Create a new instance of the file format class. Ownership passes to the
   * caller.
   */
  virtual DefaultModel* newInstance() const override
  {
    return new DefaultModel;
  }

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
   * @brief We don't have any other name beyond the identifier in the file
   */
  virtual std::string name() const override { return m_identifier; }

  /**
   * @brief This default method is defined for whatever is in a molecule
   * @return all elements - technically not true, but we don't have the mol
   */
  virtual Core::Molecule::ElementMask elements() const override
  {
    return (m_elements);
  }

  /**
   * @brief Retrieve the relevant charges from the molecule for our defined type
   */
  virtual MatrixX partialCharges(Core::Molecule& mol) const override;

protected:
  std::string m_identifier;
  Core::Molecule::ElementMask m_elements;
};

} // namespace Calc
} // namespace Avogadro

#endif // AVOGADRO_CALC_CHARGEMODEL_H

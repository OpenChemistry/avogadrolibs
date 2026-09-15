/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_CONFORMERQUANTITYTRANSLATOR_H
#define AVOGADRO_QTGUI_CONFORMERQUANTITYTRANSLATOR_H

#include "avogadroqtguiexport.h"

#include <QtCore/QObject>

namespace Avogadro {
namespace Core {
class ConformerQuantity;
}

namespace QtGui {

/**
 * @class ConformerQuantityTranslator conformerquantitytranslator.h
 * <avogadro/qtgui/conformerquantitytranslator.h>
 * @brief Internationalization of the names of per-conformer quantities.
 *
 * Core enumerates what a molecule can be measured for and works out the
 * values; this is the one place those quantities are given names a reader
 * sees, so a plot axis and a table heading cannot drift apart or be
 * translated twice. Following ElementTranslator.
 * @code
 * #include <avogadro/qtgui/conformerquantitytranslator.h>
 * ...
 * // "Dihedral 1-2-3-4"
 * ConformerQuantityTranslator::name(quantity);
 * // "Dihedral (°)"
 * ConformerQuantityTranslator::label(quantity);
 * @endcode
 */
class AVOGADROQTGUI_EXPORT ConformerQuantityTranslator : public QObject
{
  Q_OBJECT

public:
  ConformerQuantityTranslator();

  /**
   * @return what to call @p quantity: a short name naming the thing itself,
   * for a combo box entry or a column heading.
   *
   * A coordinate is named by the atoms it measures, numbered from one to
   * match the constraints dialog and the property tables.
   */
  static QString name(const Core::ConformerQuantity& quantity);

  /**
   * @return what to call @p quantity when the unit has to come with it, as on
   * an axis title or a column heading: the name from name(), with the unit in
   * parentheses after it.
   *
   * A quantity whose unit comes from the file rather than from Avogadro --
   * Energy, Forces -- has none to add unless @p unit says otherwise, so pass
   * whatever the caller converted to.
   */
  static QString label(const Core::ConformerQuantity& quantity,
                       const QString& unit = QString());
};

} // namespace QtGui
} // namespace Avogadro

#endif // AVOGADRO_QTGUI_CONFORMERQUANTITYTRANSLATOR_H

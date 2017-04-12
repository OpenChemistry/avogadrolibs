/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2007 Geoffrey R. Hutchison
  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#ifndef AVOGADRO_QTGUI_ELEMENTTRANSLATOR_H
#define AVOGADRO_QTGUI_ELEMENTTRANSLATOR_H

#include "avogadroqtguiexport.h"
#include <QtCore/QObject>

namespace Avogadro {
namespace QtGui {

/**
 * @class ElementTranslator elementtranslator.h
 * <avogadro/qtgui/elementtranslator.h>
 * @brief Internationalization of element names.
 * @author Geoff Hutchison
 *
 * This class provides for translation of element names: e.g., tr("Carbon")
 * To use the global translator:
 * @code
 * #include <avogadro/elementtranslator.h>
 * ...
 * Avogadro::elementTranslator.name(6); // Return "carbon" in English
 * @endcode
 */
class AVOGADROQTGUI_EXPORT ElementTranslator : public QObject
{
  Q_OBJECT

public:
  ElementTranslator();

  /**
   * Translate element names.
   * @param element The atomic number of the element to be translated.
   * @return a QString with the appropriate translation for the current locale.
   */
  static QString name(int element);

  /**
   * @return The highest atomic number supported by this class.
   */
  static int numberOfElements();
};

} // End namespace QtGui
} // End namespace Avogadro

#endif

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTGUI_VIEWFACTORY_H
#define AVOGADRO_QTGUI_VIEWFACTORY_H

#include "avogadroqtguiexport.h"

#include <QtWidgets/QWidget>

namespace Avogadro {
namespace QtGui {

/**
 * @class ViewFactory viewfactory.h <avogadro/qtgui/viewfactory.h>
 * @brief The ViewFactory class is a pure virtual that provides a method of
 * dynamically adding views to the MultiViewWidget class.
 * @author Marcus D. Hanwell
 */

class AVOGADROQTGUI_EXPORT ViewFactory
{
public:
  ViewFactory();
  virtual ~ViewFactory();

  /**
   * @brief Get the list of views the factory provides.
   * @return A list of supported views.
   */
  virtual QStringList views() const = 0;

  /**
   * @brief Create a named view, the caller assumes ownership of the widget.
   * @param view The name of the view.
   * @return A new widget of the requested type, nullptr if none exists.
   */
  virtual QWidget* createView(const QString& view) = 0;
};

} // End QtGui namespace
} // End Avogadro namespace

#endif // AVOGADRO_QTGUI_VIEWFACTORY_H

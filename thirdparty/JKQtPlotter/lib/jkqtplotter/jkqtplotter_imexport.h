#ifndef JKQTPLOTTER_IMPORT_H
#define JKQTPLOTTER_IMPORT_H


/*
    Copyright (c) 2008-2020 Jan W. Krieger (<jan@jkrieger.de>)

    last modification: $LastChangedDate: 2015-04-02 13:55:22 +0200 (Do, 02 Apr 2015) $  (revision $Rev: 3902 $)

    This software is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License (LGPL) as published by
    the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License (LGPL) for more details.

    You should have received a copy of the GNU Lesser General Public License (LGPL)
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/




/*! \def JKQTPLOTTER_LIB_EXPORT
    \ingroup jkqtpplottersupprt

    This define allows to export functions and classes from the jkqtcommon-library when building a dynamic/shared library.
    Usage is as follows:
    \code
        #include "jkqtplotter/jkqtplotter_imexport.h.h"

        class JKQTPLOTTER_LIB_EXPORT exportedClassName {
           ...
        };

        JKQTPLOTTER_LIB_EXPORT void exportedFunctionName();
    \endcode

    These macros append the appropriate \c Q_DECL_EXPORT and \c Q_DECL_IMPORT
    to the function/class body and thus tell windows compilers to export these sysmbols from
    the shared library, or import them from a shared library.

    Note that these attributes are only necessary on windows systems!

    These macros are controlled by two other macros:
      - \c JKQTPLOTTER_LIB_IN_DLL declares that the application should link against a shared version of
                                 JKQTPlotter, i.e. \c JKQTPlotterSharedLib_XYZ .
                                 This needs to be defined while compiling the library and while compiling
                                 any application linking against  \c JKQTPlotterSharedLib_XYZ.
      - \c JKQTPLOTTER_LIB_EXPORT_LIBRARY is only defined while compiling JKQTPlotter into \c JKQTPlotterSharedLib_XYZ
                                 and ensures thet the symbols are exported. If it is not defined (e.g. while
                                 compiling an application), the symbols are imported
    .

 */

/*! \def JKQTPLOTTER_LIB_IN_DLL
    \ingroup jkqtpplottersupprt
    \brief declares that the application should link against a shared version of
           JKQTPlotter, i.e. \c JKQTPlotterSharedLib_XYZ .
           This needs to be defined while compiling the library and while compiling
           any application linking against  \c JKQTPlotterSharedLib_XYZ.
*/

/*! \def JKQTPLOTTER_LIB_EXPORT_LIBRARY
    \ingroup jkqtpplottersupprt
    \brief is only defined while compiling JKQTPlotter into \c JKQTPlotterSharedLib_XYZ
           and ensures thet the symbols are exported. If it is not defined (e.g. while
           compiling an application), the symbols are imported
*/

#include <QtCore/QtGlobal>

#  ifdef JKQTPLOTTER_LIB_IN_DLL
#    ifndef JKQTPLOTTER_LIB_EXPORT
#      ifdef JKQTPLOTTER_LIB_EXPORT_LIBRARY
          /* We are building this library */
#        define JKQTPLOTTER_LIB_EXPORT Q_DECL_EXPORT
#      else
          /* We are using this library */
#        define JKQTPLOTTER_LIB_EXPORT Q_DECL_IMPORT
#      endif
#    endif
#  else
#    ifndef JKQTPLOTTER_LIB_EXPORT
#      define JKQTPLOTTER_LIB_EXPORT
#    endif
#  endif






#endif // JKQTPLOTTER_IMPORT_H

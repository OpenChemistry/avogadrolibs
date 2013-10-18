/**********************************************************************
  QTAIM - Extension for Quantum Theory of Atoms In Molecules Analysis

  Copyright (C) 2010 Eric C. Brown

  This file is part of the Avogadro molecular editor project.
  For more information, see <http://avogadro.openmolecules.net/>

  Some code is based on Open Babel
  For more information, see <http://openbabel.sourceforge.net/>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 ***********************************************************************/

#ifndef QTAIMEXTENSION_H
#define QTAIMEXTENSION_H

#include <avogadro/extension.h>
#include <avogadro/primitive.h>
#include <avogadro/glwidget.h>
#include "../../glpainter_p.h"

namespace Avogadro {

  class QTAIMExtension : public Extension
  {
    Q_OBJECT
    AVOGADRO_EXTENSION("QTAIM", tr("QTAIM"),
                       tr("QTAIM extension"))

  public:
    //! Constructor
    QTAIMExtension(QObject *parent=0);
    //! Deconstructor
    virtual ~QTAIMExtension();

    virtual QList<QAction *> actions() const;
    virtual QString menuPath(QAction *action) const;

    virtual QDockWidget * dockWidget();
    virtual QUndoCommand* performAction(QAction *action, GLWidget *widget);

    virtual void setMolecule(Molecule *molecule);

  private:
    QList<QAction *> m_actions;
    Molecule *m_molecule;

  private Q_SLOTS:

  };

  class QTAIMExtensionFactory : public QObject, public PluginFactory
  {
    Q_OBJECT
    Q_INTERFACES(Avogadro::PluginFactory)
        AVOGADRO_EXTENSION_FACTORY(QTAIMExtension)
      };

} // end namespace Avogadro

#endif // QTAIMEXTENSION_H

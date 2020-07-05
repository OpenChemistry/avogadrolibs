#include "constraintsextension.h"
#include "constraintsdialog.h"
#include "constraintsmodel.h"

#include <QAction>

//#include <QTextStream>
//#include <QString>

#include <string>
#include <iostream>

namespace Avogadro {
  namespace QtPlugins {
    ConstraintsExtension::ConstraintsExtension(QObject* p) : ExtensionPlugin(p)
    {
      QAction* action = new QAction(this);
      action->setEnabled(true);
      action->setText(tr("Constraints"));
      connect(action, SIGNAL(triggered()), SLOT(onDialog()));
      m_actions.push_back(action);

      dialog = new ConstraintsDialog(this,
                                     qobject_cast<QWidget*>(parent()));

    }

    ConstraintsExtension::~ConstraintsExtension(){}

    QList<QAction*> ConstraintsExtension::actions() const{
      return m_actions;
      }

    QStringList ConstraintsExtension::menuPath(QAction*) const{
      return QStringList() << tr("&Extensions");
    }

    
    void ConstraintsExtension::onDialog()
    {
      dialog->show();
      
    }
    

    void ConstraintsExtension::setMolecule(QtGui::Molecule* mol)
    {
      if (mol != m_molecule)
        m_molecule = mol;
      if (!m_molecule->constraints)
        m_molecule->constraints = new ConstraintsModel();
      dialog->setModel();
    }

    bool ConstraintsExtension::readMolecule(QtGui::Molecule& mol){
      return true;
    }
  }
}

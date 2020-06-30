#include "constraintsextension.h"
#include "constraintsdialog.h"
#include "constraintsmodel.h"

#include <QAction>
#include <QtWidgets/QMessageBox>
#include <QTextStream>
#include <QString>

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

      dialog = new ConstraintsDialog(qobject_cast<QWidget*>(parent()));

    }

    ConstraintsExtension::~ConstraintsExtension(){}

    QList<QAction*> ConstraintsExtension::actions() const{
      return m_actions;
      }

    QStringList ConstraintsExtension::menuPath(QAction*) const{
      return QStringList() << tr("&Extensions");
    }

    
    void ConstraintsExtension::onDialog()
    {/*
      if (!dialog)
        {
          dialog = new ConstraintsDialog(qobject_cast<QWidget*>(parent()));
          }*/
      dialog->show();
      //ConstraintsDialog dlg(qobject_cast<QWidget*>(parent()));
      //dlg.show();
      /*
      QMessageBox::critical(qobject_cast<QWidget*>(parent()), tr("Error"),
                            tr("I could open you"),
                            QMessageBox::Ok);
      */
      /*
      ConstraintsDialog dlg;
      dlg.whow();
      */

      //ConstraintsDialog::whow(qobject_cast<QWidget*>(parent()));

      /*
      QTextStream out(stdout);

      ConstraintsDialog dlg(qobject_cast<QWidget*>(parent()));
      QString test = dlg.whow();
      out << test;
      */
      
    }
    

    void ConstraintsExtension::setMolecule(QtGui::Molecule* mol)
    {
      if (mol != m_molecule)
        m_molecule = mol;
      if (!m_molecule->constraints)
        m_molecule->constraints = new ConstraintsModel();
      dialog->setModel(m_molecule->constraints);
      // update dialog with constraint info (if any) from mol object
    }

    bool ConstraintsExtension::readMolecule(QtGui::Molecule& mol){
      return true;
    }
  }
}

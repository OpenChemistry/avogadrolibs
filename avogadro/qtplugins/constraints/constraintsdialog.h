#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#include "constraintsextension.h"
#include "constraintsmodel.h"
#include <QDialog>
#include <QButtonGroup>
#include <QModelIndex>
#include <QTableView>
#include <QString>
#include <string>

namespace Avogadro {
  namespace QtPlugins {
    namespace Ui {
      class ConstraintsDialog;
    }
    class ConstraintsDialog : public QDialog
    {
      Q_OBJECT

    public:
      explicit ConstraintsDialog(ConstraintsExtension* plugin ,
                                 QWidget* parent_=0,
                                 Qt::WindowFlags f = 0);
      ~ConstraintsDialog() override;
      void setModel();
      
    public slots:
      void acceptConstraints();
      void addConstraint();
      void deleteConstraint();
      void deleteAllConstraints();
      void highlightSelected();
      void connectHighlight(int state);

    private:
      Ui::ConstraintsDialog* ui;
      ConstraintsExtension* m_plugin;
      
    };
  }
}
#endif //AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H

#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H

#include <QDialog>
#include <QButtonGroup>
#include <QModelIndex>
#include <QTableView>

namespace Avogadro {
  namespace QtPlugins {
    namespace Ui {
      class ConstraintsDialog;
    }
    class ConstraintsDialog : public QDialog
    {
      Q_OBJECT

    public:
      explicit ConstraintsDialog(QWidget* parent_=0);
      ~ConstraintsDialog() override;

      void whow();

    private:
      Ui::ConstraintsDialog* ui;
    };
  }
}
#endif //AVOGADRO_QTPLUGINS_CONSTRAINTSDIALOG_H

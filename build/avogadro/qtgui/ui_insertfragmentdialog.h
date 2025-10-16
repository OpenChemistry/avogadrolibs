/********************************************************************************
** Form generated from reading UI file 'insertfragmentdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INSERTFRAGMENTDIALOG_H
#define UI_INSERTFRAGMENTDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtGui {

class Ui_InsertFragmentDialog
{
public:
    QVBoxLayout *vboxLayout;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *filterLineEdit;
    QGridLayout *gridLayout;
    QTreeView *directoryTreeView;
    QToolButton *preview;
    QFrame *line_2;
    QHBoxLayout *hboxLayout;
    QSpacerItem *spacerItem;
    QPushButton *insertFragmentButton;
    QSpacerItem *spacerItem1;

    void setupUi(QDialog *Avogadro__QtGui__InsertFragmentDialog)
    {
        if (Avogadro__QtGui__InsertFragmentDialog->objectName().isEmpty())
            Avogadro__QtGui__InsertFragmentDialog->setObjectName(QString::fromUtf8("Avogadro__QtGui__InsertFragmentDialog"));
        Avogadro__QtGui__InsertFragmentDialog->resize(412, 376);
        vboxLayout = new QVBoxLayout(Avogadro__QtGui__InsertFragmentDialog);
        vboxLayout->setObjectName(QString::fromUtf8("vboxLayout"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(Avogadro__QtGui__InsertFragmentDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        filterLineEdit = new QLineEdit(Avogadro__QtGui__InsertFragmentDialog);
        filterLineEdit->setObjectName(QString::fromUtf8("filterLineEdit"));
        filterLineEdit->setStyleSheet(QString::fromUtf8("border-radius: 4px;"));
        filterLineEdit->setClearButtonEnabled(true);

        horizontalLayout->addWidget(filterLineEdit);


        vboxLayout->addLayout(horizontalLayout);

        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        directoryTreeView = new QTreeView(Avogadro__QtGui__InsertFragmentDialog);
        directoryTreeView->setObjectName(QString::fromUtf8("directoryTreeView"));

        gridLayout->addWidget(directoryTreeView, 0, 0, 1, 1);

        preview = new QToolButton(Avogadro__QtGui__InsertFragmentDialog);
        preview->setObjectName(QString::fromUtf8("preview"));
        preview->setIconSize(QSize(128, 128));

        gridLayout->addWidget(preview, 0, 1, 1, 1);


        vboxLayout->addLayout(gridLayout);

        line_2 = new QFrame(Avogadro__QtGui__InsertFragmentDialog);
        line_2->setObjectName(QString::fromUtf8("line_2"));
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);

        vboxLayout->addWidget(line_2);

        hboxLayout = new QHBoxLayout();
        hboxLayout->setObjectName(QString::fromUtf8("hboxLayout"));
        spacerItem = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        insertFragmentButton = new QPushButton(Avogadro__QtGui__InsertFragmentDialog);
        insertFragmentButton->setObjectName(QString::fromUtf8("insertFragmentButton"));
        insertFragmentButton->setFlat(false);

        hboxLayout->addWidget(insertFragmentButton);

        spacerItem1 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem1);


        vboxLayout->addLayout(hboxLayout);


        retranslateUi(Avogadro__QtGui__InsertFragmentDialog);

        insertFragmentButton->setDefault(true);


        QMetaObject::connectSlotsByName(Avogadro__QtGui__InsertFragmentDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtGui__InsertFragmentDialog)
    {
        Avogadro__QtGui__InsertFragmentDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtGui::InsertFragmentDialog", "Insert Fragment\342\200\246", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtGui::InsertFragmentDialog", "Filter:", nullptr));
#if QT_CONFIG(tooltip)
        filterLineEdit->setToolTip(QCoreApplication::translate("Avogadro::QtGui::InsertFragmentDialog", "Type a name or part of a name to show only matching files.", nullptr));
#endif // QT_CONFIG(tooltip)
        preview->setText(QString());
        insertFragmentButton->setText(QCoreApplication::translate("Avogadro::QtGui::InsertFragmentDialog", "Insert", nullptr));
    } // retranslateUi

};

} // namespace QtGui
} // namespace Avogadro

namespace Avogadro {
namespace QtGui {
namespace Ui {
    class InsertFragmentDialog: public Ui_InsertFragmentDialog {};
} // namespace Ui
} // namespace QtGui
} // namespace Avogadro

#endif // UI_INSERTFRAGMENTDIALOG_H

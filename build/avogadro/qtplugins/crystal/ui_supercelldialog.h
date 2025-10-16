/********************************************************************************
** Form generated from reading UI file 'supercelldialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_SUPERCELLDIALOG_H
#define UI_SUPERCELLDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>

namespace Avogadro {
namespace QtPlugins {

class Ui_SupercellDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QGridLayout *gridLayout;
    QGroupBox *groupBox;
    QGridLayout *gridLayout1;
    QLabel *aRepeatLabel;
    QSpinBox *aCellSpinBox;
    QLabel *bRepeatLabel;
    QSpinBox *bCellSpinBox;
    QLabel *cRepeatLabel;
    QSpinBox *cCellSpinBox;
    QDialogButtonBox *ok_cancel_bb;
    QSpacerItem *verticalSpacer;

    void setupUi(QDialog *Avogadro__QtPlugins__SupercellDialog)
    {
        if (Avogadro__QtPlugins__SupercellDialog->objectName().isEmpty())
            Avogadro__QtPlugins__SupercellDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__SupercellDialog"));
        Avogadro__QtPlugins__SupercellDialog->resize(324, 188);
        verticalLayout_2 = new QVBoxLayout(Avogadro__QtPlugins__SupercellDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        groupBox = new QGroupBox(Avogadro__QtPlugins__SupercellDialog);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        gridLayout1 = new QGridLayout(groupBox);
        gridLayout1->setObjectName(QString::fromUtf8("gridLayout1"));
        aRepeatLabel = new QLabel(groupBox);
        aRepeatLabel->setObjectName(QString::fromUtf8("aRepeatLabel"));

        gridLayout1->addWidget(aRepeatLabel, 0, 0, 1, 1);

        aCellSpinBox = new QSpinBox(groupBox);
        aCellSpinBox->setObjectName(QString::fromUtf8("aCellSpinBox"));
        aCellSpinBox->setMinimum(1);

        gridLayout1->addWidget(aCellSpinBox, 0, 1, 1, 1);

        bRepeatLabel = new QLabel(groupBox);
        bRepeatLabel->setObjectName(QString::fromUtf8("bRepeatLabel"));

        gridLayout1->addWidget(bRepeatLabel, 1, 0, 1, 1);

        bCellSpinBox = new QSpinBox(groupBox);
        bCellSpinBox->setObjectName(QString::fromUtf8("bCellSpinBox"));
        bCellSpinBox->setMinimum(1);

        gridLayout1->addWidget(bCellSpinBox, 1, 1, 1, 1);

        cRepeatLabel = new QLabel(groupBox);
        cRepeatLabel->setObjectName(QString::fromUtf8("cRepeatLabel"));

        gridLayout1->addWidget(cRepeatLabel, 2, 0, 1, 1);

        cCellSpinBox = new QSpinBox(groupBox);
        cCellSpinBox->setObjectName(QString::fromUtf8("cCellSpinBox"));
        cCellSpinBox->setMinimum(1);

        gridLayout1->addWidget(cCellSpinBox, 2, 1, 1, 1);


        gridLayout->addWidget(groupBox, 0, 0, 1, 2);


        verticalLayout_2->addLayout(gridLayout);

        ok_cancel_bb = new QDialogButtonBox(Avogadro__QtPlugins__SupercellDialog);
        ok_cancel_bb->setObjectName(QString::fromUtf8("ok_cancel_bb"));
        ok_cancel_bb->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout_2->addWidget(ok_cancel_bb);

        verticalSpacer = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);


        retranslateUi(Avogadro__QtPlugins__SupercellDialog);
        QObject::connect(ok_cancel_bb, SIGNAL(accepted()), Avogadro__QtPlugins__SupercellDialog, SLOT(accept()));
        QObject::connect(ok_cancel_bb, SIGNAL(rejected()), Avogadro__QtPlugins__SupercellDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__SupercellDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__SupercellDialog)
    {
        Avogadro__QtPlugins__SupercellDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::SupercellDialog", "Supercell Parameters", nullptr));
        groupBox->setTitle(QCoreApplication::translate("Avogadro::QtPlugins::SupercellDialog", "Super Cell Options", nullptr));
        aRepeatLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SupercellDialog", "A repeat:", nullptr));
        bRepeatLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SupercellDialog", "B repeat:", nullptr));
        cRepeatLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::SupercellDialog", "C repeat:", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class SupercellDialog: public Ui_SupercellDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_SUPERCELLDIALOG_H

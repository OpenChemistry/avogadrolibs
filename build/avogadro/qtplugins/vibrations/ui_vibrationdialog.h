/********************************************************************************
** Form generated from reading UI file 'vibrationdialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_VIBRATIONDIALOG_H
#define UI_VIBRATIONDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSlider>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTableView>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_VibrationDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTableView *tableView;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QSlider *amplitudeSlider;
    QHBoxLayout *horizontalLayout_2;
    QSpacerItem *horizontalSpacer;
    QPushButton *startButton;
    QPushButton *stopButton;

    void setupUi(QDialog *VibrationDialog)
    {
        if (VibrationDialog->objectName().isEmpty())
            VibrationDialog->setObjectName(QString::fromUtf8("VibrationDialog"));
        VibrationDialog->resize(500, 600);
        verticalLayout = new QVBoxLayout(VibrationDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        verticalLayout->setContentsMargins(5, 5, 5, 5);
        tableView = new QTableView(VibrationDialog);
        tableView->setObjectName(QString::fromUtf8("tableView"));
        tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableView->setProperty("showDropIndicator", QVariant(false));
        tableView->setDragDropOverwriteMode(false);
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

        verticalLayout->addWidget(tableView);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(VibrationDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        amplitudeSlider = new QSlider(VibrationDialog);
        amplitudeSlider->setObjectName(QString::fromUtf8("amplitudeSlider"));
        amplitudeSlider->setValue(20);
        amplitudeSlider->setOrientation(Qt::Horizontal);
        amplitudeSlider->setTickPosition(QSlider::TicksBothSides);
        amplitudeSlider->setTickInterval(10);

        horizontalLayout->addWidget(amplitudeSlider);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_2->addItem(horizontalSpacer);

        startButton = new QPushButton(VibrationDialog);
        startButton->setObjectName(QString::fromUtf8("startButton"));

        horizontalLayout_2->addWidget(startButton);

        stopButton = new QPushButton(VibrationDialog);
        stopButton->setObjectName(QString::fromUtf8("stopButton"));

        horizontalLayout_2->addWidget(stopButton);


        verticalLayout->addLayout(horizontalLayout_2);


        retranslateUi(VibrationDialog);

        QMetaObject::connectSlotsByName(VibrationDialog);
    } // setupUi

    void retranslateUi(QDialog *VibrationDialog)
    {
        VibrationDialog->setWindowTitle(QCoreApplication::translate("VibrationDialog", "Vibrational Modes", nullptr));
        label->setText(QCoreApplication::translate("VibrationDialog", "Amplitude:", nullptr));
        startButton->setText(QCoreApplication::translate("VibrationDialog", "Start Animation", nullptr));
        stopButton->setText(QCoreApplication::translate("VibrationDialog", "Stop Animation", nullptr));
    } // retranslateUi

};

namespace Ui {
    class VibrationDialog: public Ui_VibrationDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_VIBRATIONDIALOG_H

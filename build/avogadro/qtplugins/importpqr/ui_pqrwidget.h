/********************************************************************************
** Form generated from reading UI file 'pqrwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PQRWIDGET_H
#define UI_PQRWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_PQRWidget
{
public:
    QHBoxLayout *horizontalLayout;
    QGridLayout *gridLayout;
    QPushButton *searchButton;
    QLineEdit *molName;
    QComboBox *searchTypeBox;
    QLabel *label;
    QLineEdit *nameDisplay;
    QLabel *formulaDisplay;
    QLabel *label_5;
    QTableWidget *tableWidget;
    QPushButton *downloadButton;
    QLabel *label_4;
    QLabel *pngPreview;

    void setupUi(QWidget *PQRWidget)
    {
        if (PQRWidget->objectName().isEmpty())
            PQRWidget->setObjectName(QString::fromUtf8("PQRWidget"));
        PQRWidget->resize(1087, 674);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(PQRWidget->sizePolicy().hasHeightForWidth());
        PQRWidget->setSizePolicy(sizePolicy);
        horizontalLayout = new QHBoxLayout(PQRWidget);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        gridLayout = new QGridLayout();
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        searchButton = new QPushButton(PQRWidget);
        searchButton->setObjectName(QString::fromUtf8("searchButton"));
        QSizePolicy sizePolicy1(QSizePolicy::Minimum, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(searchButton->sizePolicy().hasHeightForWidth());
        searchButton->setSizePolicy(sizePolicy1);

        gridLayout->addWidget(searchButton, 2, 6, 1, 1);

        molName = new QLineEdit(PQRWidget);
        molName->setObjectName(QString::fromUtf8("molName"));

        gridLayout->addWidget(molName, 2, 1, 1, 1);

        searchTypeBox = new QComboBox(PQRWidget);
        searchTypeBox->addItem(QString());
        searchTypeBox->addItem(QString());
        searchTypeBox->addItem(QString());
        searchTypeBox->addItem(QString());
        searchTypeBox->addItem(QString());
        searchTypeBox->setObjectName(QString::fromUtf8("searchTypeBox"));
        sizePolicy1.setHeightForWidth(searchTypeBox->sizePolicy().hasHeightForWidth());
        searchTypeBox->setSizePolicy(sizePolicy1);

        gridLayout->addWidget(searchTypeBox, 2, 5, 1, 1);

        label = new QLabel(PQRWidget);
        label->setObjectName(QString::fromUtf8("label"));
        QSizePolicy sizePolicy2(QSizePolicy::Fixed, QSizePolicy::Preferred);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy2);

        gridLayout->addWidget(label, 2, 0, 1, 1);

        nameDisplay = new QLineEdit(PQRWidget);
        nameDisplay->setObjectName(QString::fromUtf8("nameDisplay"));
        nameDisplay->setReadOnly(true);

        gridLayout->addWidget(nameDisplay, 4, 6, 1, 1);

        formulaDisplay = new QLabel(PQRWidget);
        formulaDisplay->setObjectName(QString::fromUtf8("formulaDisplay"));

        gridLayout->addWidget(formulaDisplay, 5, 6, 1, 1);

        label_5 = new QLabel(PQRWidget);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        gridLayout->addWidget(label_5, 5, 5, 1, 1);

        tableWidget = new QTableWidget(PQRWidget);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        QSizePolicy sizePolicy3(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy3.setHorizontalStretch(5);
        sizePolicy3.setVerticalStretch(0);
        sizePolicy3.setHeightForWidth(tableWidget->sizePolicy().hasHeightForWidth());
        tableWidget->setSizePolicy(sizePolicy3);
        tableWidget->setMinimumSize(QSize(750, 500));

        gridLayout->addWidget(tableWidget, 3, 0, 1, 2);

        downloadButton = new QPushButton(PQRWidget);
        downloadButton->setObjectName(QString::fromUtf8("downloadButton"));
        downloadButton->setEnabled(false);

        gridLayout->addWidget(downloadButton, 9, 5, 1, 1);

        label_4 = new QLabel(PQRWidget);
        label_4->setObjectName(QString::fromUtf8("label_4"));

        gridLayout->addWidget(label_4, 4, 5, 1, 1);

        pngPreview = new QLabel(PQRWidget);
        pngPreview->setObjectName(QString::fromUtf8("pngPreview"));
        QSizePolicy sizePolicy4(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy4.setHorizontalStretch(0);
        sizePolicy4.setVerticalStretch(0);
        sizePolicy4.setHeightForWidth(pngPreview->sizePolicy().hasHeightForWidth());
        pngPreview->setSizePolicy(sizePolicy4);
        pngPreview->setMinimumSize(QSize(300, 300));
        pngPreview->setMaximumSize(QSize(300, 300));

        gridLayout->addWidget(pngPreview, 3, 5, 1, 2);


        horizontalLayout->addLayout(gridLayout);


        retranslateUi(PQRWidget);

        QMetaObject::connectSlotsByName(PQRWidget);
    } // setupUi

    void retranslateUi(QWidget *PQRWidget)
    {
        PQRWidget->setWindowTitle(QCoreApplication::translate("PQRWidget", "Import From PQR\342\200\246", nullptr));
        searchButton->setText(QCoreApplication::translate("PQRWidget", "Search", nullptr));
        searchTypeBox->setItemText(0, QCoreApplication::translate("PQRWidget", "name", nullptr));
        searchTypeBox->setItemText(1, QCoreApplication::translate("PQRWidget", "tag", nullptr));
        searchTypeBox->setItemText(2, QCoreApplication::translate("PQRWidget", "synonym", nullptr));
        searchTypeBox->setItemText(3, QCoreApplication::translate("PQRWidget", "formula", nullptr));
        searchTypeBox->setItemText(4, QCoreApplication::translate("PQRWidget", "inchi", nullptr));

        label->setText(QCoreApplication::translate("PQRWidget", "Search By: ", nullptr));
        formulaDisplay->setText(QString());
        label_5->setText(QCoreApplication::translate("PQRWidget", "Formula:", nullptr));
        downloadButton->setText(QCoreApplication::translate("PQRWidget", "Download", nullptr));
        label_4->setText(QCoreApplication::translate("PQRWidget", "Name:", nullptr));
        pngPreview->setText(QString());
    } // retranslateUi

};

namespace Ui {
    class PQRWidget: public Ui_PQRWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PQRWIDGET_H

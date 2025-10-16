/********************************************************************************
** Form generated from reading UI file 'downloaderwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DOWNLOADERWIDGET_H
#define UI_DOWNLOADERWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextBrowser>

QT_BEGIN_NAMESPACE

class Ui_DownloaderWidget
{
public:
    QGridLayout *gridLayout;
    QPushButton *downloadButton;
    QTableWidget *repoTable;
    QTextBrowser *readmeBrowser;

    void setupUi(QDialog *DownloaderWidget)
    {
        if (DownloaderWidget->objectName().isEmpty())
            DownloaderWidget->setObjectName(QString::fromUtf8("DownloaderWidget"));
        DownloaderWidget->resize(965, 432);
        gridLayout = new QGridLayout(DownloaderWidget);
        gridLayout->setObjectName(QString::fromUtf8("gridLayout"));
        downloadButton = new QPushButton(DownloaderWidget);
        downloadButton->setObjectName(QString::fromUtf8("downloadButton"));

        gridLayout->addWidget(downloadButton, 1, 0, 1, 1);

        repoTable = new QTableWidget(DownloaderWidget);
        repoTable->setObjectName(QString::fromUtf8("repoTable"));

        gridLayout->addWidget(repoTable, 0, 0, 1, 1);

        readmeBrowser = new QTextBrowser(DownloaderWidget);
        readmeBrowser->setObjectName(QString::fromUtf8("readmeBrowser"));

        gridLayout->addWidget(readmeBrowser, 0, 1, 1, 1);


        retranslateUi(DownloaderWidget);

        QMetaObject::connectSlotsByName(DownloaderWidget);
    } // setupUi

    void retranslateUi(QDialog *DownloaderWidget)
    {
        DownloaderWidget->setWindowTitle(QCoreApplication::translate("DownloaderWidget", "Download Plugins\342\200\246", nullptr));
        downloadButton->setText(QCoreApplication::translate("DownloaderWidget", "Download Selected", nullptr));
    } // retranslateUi

};

namespace Ui {
    class DownloaderWidget: public Ui_DownloaderWidget {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DOWNLOADERWIDGET_H

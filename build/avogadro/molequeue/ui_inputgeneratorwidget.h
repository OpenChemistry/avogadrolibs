/********************************************************************************
** Form generated from reading UI file 'inputgeneratorwidget.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_INPUTGENERATORWIDGET_H
#define UI_INPUTGENERATORWIDGET_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace Avogadro {
namespace MoleQueue {

class Ui_InputGeneratorWidget
{
public:
    QVBoxLayout *verticalLayout_2;
    QGroupBox *groupBox2;
    QHBoxLayout *horizontalLayout;
    QWidget *optionsWidget;
    QTabWidget *tabWidget;
    QFrame *warningBox;
    QVBoxLayout *verticalLayout;
    QTextBrowser *warningText;
    QHBoxLayout *horizontalLayout_4;
    QSpacerItem *horizontalSpacer;
    QPushButton *warningTextButton;
    QHBoxLayout *hboxLayout;
    QPushButton *defaultsButton;
    QCheckBox *debugCheckBox;
    QSpacerItem *spacerItem;
    QPushButton *computeButton;
    QPushButton *generateButton;
    QPushButton *closeButton;

    void setupUi(QWidget *Avogadro__MoleQueue__InputGeneratorWidget)
    {
        if (Avogadro__MoleQueue__InputGeneratorWidget->objectName().isEmpty())
            Avogadro__MoleQueue__InputGeneratorWidget->setObjectName(QString::fromUtf8("Avogadro__MoleQueue__InputGeneratorWidget"));
        Avogadro__MoleQueue__InputGeneratorWidget->resize(813, 650);
        verticalLayout_2 = new QVBoxLayout(Avogadro__MoleQueue__InputGeneratorWidget);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        groupBox2 = new QGroupBox(Avogadro__MoleQueue__InputGeneratorWidget);
        groupBox2->setObjectName(QString::fromUtf8("groupBox2"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(groupBox2->sizePolicy().hasHeightForWidth());
        groupBox2->setSizePolicy(sizePolicy);
        horizontalLayout = new QHBoxLayout(groupBox2);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        optionsWidget = new QWidget(groupBox2);
        optionsWidget->setObjectName(QString::fromUtf8("optionsWidget"));

        horizontalLayout->addWidget(optionsWidget);


        verticalLayout_2->addWidget(groupBox2);

        tabWidget = new QTabWidget(Avogadro__MoleQueue__InputGeneratorWidget);
        tabWidget->setObjectName(QString::fromUtf8("tabWidget"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(tabWidget->sizePolicy().hasHeightForWidth());
        tabWidget->setSizePolicy(sizePolicy1);

        verticalLayout_2->addWidget(tabWidget);

        warningBox = new QFrame(Avogadro__MoleQueue__InputGeneratorWidget);
        warningBox->setObjectName(QString::fromUtf8("warningBox"));
        verticalLayout = new QVBoxLayout(warningBox);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        warningText = new QTextBrowser(warningBox);
        warningText->setObjectName(QString::fromUtf8("warningText"));

        verticalLayout->addWidget(warningText);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_4->addItem(horizontalSpacer);

        warningTextButton = new QPushButton(warningBox);
        warningTextButton->setObjectName(QString::fromUtf8("warningTextButton"));

        horizontalLayout_4->addWidget(warningTextButton);


        verticalLayout->addLayout(horizontalLayout_4);


        verticalLayout_2->addWidget(warningBox);

        hboxLayout = new QHBoxLayout();
        hboxLayout->setObjectName(QString::fromUtf8("hboxLayout"));
        defaultsButton = new QPushButton(Avogadro__MoleQueue__InputGeneratorWidget);
        defaultsButton->setObjectName(QString::fromUtf8("defaultsButton"));
        defaultsButton->setEnabled(true);

        hboxLayout->addWidget(defaultsButton);

        debugCheckBox = new QCheckBox(Avogadro__MoleQueue__InputGeneratorWidget);
        debugCheckBox->setObjectName(QString::fromUtf8("debugCheckBox"));

        hboxLayout->addWidget(debugCheckBox);

        spacerItem = new QSpacerItem(13, 20, QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);

        hboxLayout->addItem(spacerItem);

        computeButton = new QPushButton(Avogadro__MoleQueue__InputGeneratorWidget);
        computeButton->setObjectName(QString::fromUtf8("computeButton"));

        hboxLayout->addWidget(computeButton);

        generateButton = new QPushButton(Avogadro__MoleQueue__InputGeneratorWidget);
        generateButton->setObjectName(QString::fromUtf8("generateButton"));

        hboxLayout->addWidget(generateButton);

        closeButton = new QPushButton(Avogadro__MoleQueue__InputGeneratorWidget);
        closeButton->setObjectName(QString::fromUtf8("closeButton"));

        hboxLayout->addWidget(closeButton);


        verticalLayout_2->addLayout(hboxLayout);


        retranslateUi(Avogadro__MoleQueue__InputGeneratorWidget);

        QMetaObject::connectSlotsByName(Avogadro__MoleQueue__InputGeneratorWidget);
    } // setupUi

    void retranslateUi(QWidget *Avogadro__MoleQueue__InputGeneratorWidget)
    {
        Avogadro__MoleQueue__InputGeneratorWidget->setWindowTitle(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Form", nullptr));
        groupBox2->setTitle(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Calculation Settings", nullptr));
        warningTextButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Placeholder text\342\200\246", nullptr));
        defaultsButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Reset", nullptr));
        debugCheckBox->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Debug Script\342\200\246", nullptr));
        computeButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Submit Calculation\342\200\246", nullptr));
        generateButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Save Input\342\200\246", nullptr));
        closeButton->setText(QCoreApplication::translate("Avogadro::MoleQueue::InputGeneratorWidget", "Close", nullptr));
    } // retranslateUi

};

} // namespace MoleQueue
} // namespace Avogadro

namespace Avogadro {
namespace MoleQueue {
namespace Ui {
    class InputGeneratorWidget: public Ui_InputGeneratorWidget {};
} // namespace Ui
} // namespace MoleQueue
} // namespace Avogadro

#endif // UI_INPUTGENERATORWIDGET_H

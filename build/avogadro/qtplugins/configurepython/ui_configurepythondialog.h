/********************************************************************************
** Form generated from reading UI file 'configurepythondialog.ui'
**
** Created by: Qt User Interface Compiler version 5.15.17
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CONFIGUREPYTHONDIALOG_H
#define UI_CONFIGUREPYTHONDIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include <avogadro/qtgui/filebrowsewidget.h>

namespace Avogadro {
namespace QtPlugins {

class Ui_ConfigurePythonDialog
{
public:
    QVBoxLayout *verticalLayout_2;
    QLabel *textLabel;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QComboBox *environmentCombo;
    QSpacerItem *horizontalSpacer;
    QtGui::FileBrowseWidget *browseWidget;
    QSpacerItem *verticalSpacer;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *Avogadro__QtPlugins__ConfigurePythonDialog)
    {
        if (Avogadro__QtPlugins__ConfigurePythonDialog->objectName().isEmpty())
            Avogadro__QtPlugins__ConfigurePythonDialog->setObjectName(QString::fromUtf8("Avogadro__QtPlugins__ConfigurePythonDialog"));
        Avogadro__QtPlugins__ConfigurePythonDialog->resize(376, 166);
        QSizePolicy sizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(Avogadro__QtPlugins__ConfigurePythonDialog->sizePolicy().hasHeightForWidth());
        Avogadro__QtPlugins__ConfigurePythonDialog->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(Avogadro__QtPlugins__ConfigurePythonDialog);
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        textLabel = new QLabel(Avogadro__QtPlugins__ConfigurePythonDialog);
        textLabel->setObjectName(QString::fromUtf8("textLabel"));

        verticalLayout_2->addWidget(textLabel);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        label = new QLabel(Avogadro__QtPlugins__ConfigurePythonDialog);
        label->setObjectName(QString::fromUtf8("label"));

        horizontalLayout->addWidget(label);

        environmentCombo = new QComboBox(Avogadro__QtPlugins__ConfigurePythonDialog);
        environmentCombo->setObjectName(QString::fromUtf8("environmentCombo"));

        horizontalLayout->addWidget(environmentCombo);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);


        verticalLayout_2->addLayout(horizontalLayout);

        browseWidget = new QtGui::FileBrowseWidget(Avogadro__QtPlugins__ConfigurePythonDialog);
        browseWidget->setObjectName(QString::fromUtf8("browseWidget"));
        browseWidget->setEnabled(false);

        verticalLayout_2->addWidget(browseWidget);

        verticalSpacer = new QSpacerItem(20, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);

        buttonBox = new QDialogButtonBox(Avogadro__QtPlugins__ConfigurePythonDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        verticalLayout_2->addWidget(buttonBox);


        retranslateUi(Avogadro__QtPlugins__ConfigurePythonDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), Avogadro__QtPlugins__ConfigurePythonDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), Avogadro__QtPlugins__ConfigurePythonDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(Avogadro__QtPlugins__ConfigurePythonDialog);
    } // setupUi

    void retranslateUi(QDialog *Avogadro__QtPlugins__ConfigurePythonDialog)
    {
        Avogadro__QtPlugins__ConfigurePythonDialog->setWindowTitle(QCoreApplication::translate("Avogadro::QtPlugins::ConfigurePythonDialog", "Python Settings\342\200\246", nullptr));
        textLabel->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConfigurePythonDialog", "Select the Python version used to run scripts.\n"
"Avogadro must be restarted for any changes to take effect.", nullptr));
        label->setText(QCoreApplication::translate("Avogadro::QtPlugins::ConfigurePythonDialog", "Environment:", nullptr));
    } // retranslateUi

};

} // namespace QtPlugins
} // namespace Avogadro

namespace Avogadro {
namespace QtPlugins {
namespace Ui {
    class ConfigurePythonDialog: public Ui_ConfigurePythonDialog {};
} // namespace Ui
} // namespace QtPlugins
} // namespace Avogadro

#endif // UI_CONFIGUREPYTHONDIALOG_H

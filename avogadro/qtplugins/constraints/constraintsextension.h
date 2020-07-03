#ifndef AVOGADRO_QTPLUGINS_CONSTRAINTS_H
#define AVOGADRO_QTPLUGINS_CONSTRAINTS_H

#include <avogadro/qtgui/extensionplugin.h>
#include <QtCore/QMap>

class QAction;

namespace Avogadro {
  namespace QtPlugins {
    class ConstraintsDialog;

    class ConstraintsExtension : public QtGui::ExtensionPlugin
    {
      Q_OBJECT

    public:
      explicit ConstraintsExtension(QObject* parent=0);
      ~ConstraintsExtension() override;

      QString name() const override { return tr("Constraints");}

      QString description() const override {
        return tr("Set Constraints for MM and QM optimizations");
      }

      QList<QAction*> actions() const override;

      QStringList menuPath(QAction*) const override;

      void setMolecule(QtGui::Molecule* mol) override;

      bool readMolecule(QtGui::Molecule& mol) override;

    private slots:
      void onDialog();

    private:
      QList<QAction*> m_actions;
      QtGui::Molecule* m_molecule = nullptr;
      ConstraintsDialog* dialog = nullptr;

      friend class ConstraintsDialog;
    };
  }
}

#endif // AVOGADRO_QTPLUGINS_CONSTRAINTS_H

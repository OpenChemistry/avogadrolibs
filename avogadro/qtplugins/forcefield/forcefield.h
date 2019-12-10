/******************************************************************************
  This source file is part of the Avogadro project.

  This source code is released under the New BSD License, (the "License").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_FORCEFIELD_H
#define AVOGADRO_QTPLUGINS_FORCEFIELD_H

#include <avogadro/qtgui/extensionplugin.h>

#include <QtCore/QMultiMap>
#include <QtCore/QStringList>

class QAction;
class QDialog;

namespace Avogadro {
namespace QtPlugins {

/**
 * @brief The Forcefield class implements the extension interface for
 *  forcefield (and other) optimization
 * @author Geoffrey R. Hutchison
 */
class Forcefield : public QtGui::ExtensionPlugin
{
  Q_OBJECT

public:
  enum Minimizer
  {
    SteepestDescent = 0,
    ConjugateGradients,
    LBFGS,
    FIRE,
  };

  explicit Forcefield(QObject* parent = 0);
  ~Forcefield() override;

  QString name() const override { return tr("Forcefield optimization"); }

  QString description() const override
  {
    return tr("Forcefield minimization, including scripts");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction*) const override;

  void setMolecule(QtGui::Molecule* mol) override;

public slots:
  /**
   * Scan for new scripts in the Forcefield directories.
   */
  void refreshScripts();

private slots:
  void energy();
  void optimize();

private:
  QList<QAction*> m_actions;
  QtGui::Molecule* m_molecule;

  Minimizer m_minimizer;
  unsigned int m_method;
  unsigned int m_maxSteps;

  // maps program name --> script file path
  QMap<QString, QString> m_forcefieldScripts;

  const Io::FileFormat* m_outputFormat;
  QString m_tempFileName;
};
}
}

#endif // AVOGADRO_QTPLUGINS_FORCEFIELD_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#ifndef AVOGADRO_QTPLUGINS_CENTROID_H
#define AVOGADRO_QTPLUGINS_CENTROID_H

#include <avogadro/core/avogadrocore.h>
#include <avogadro/qtgui/extensionplugin.h>

namespace Avogadro::QtPlugins {

/**
 * @brief The Centroid class adds centroids and center-of-mass
 */
class Centroid : public QtGui::ExtensionPlugin
{
  Q_OBJECT
public:
  explicit Centroid(QObject* parent_ = nullptr);
  ~Centroid() override = default;

  QString name() const override { return tr("Centroid"); }

  QString description() const override
  {
    return tr("Add centroids and center-of-mass.");
  }

  QList<QAction*> actions() const override;

  QStringList menuPath(QAction* action) const override;

public slots:
  void setMolecule(QtGui::Molecule* mol) override;

private slots:
  void addCentroid();
  void addCenterOfMass();
  void normal();

private:
  QtGui::Molecule* m_molecule;

  QAction* m_centroidAction;
  QAction* m_comAction;
  QAction* m_normalAction;
};

} // namespace Avogadro::QtPlugins

#endif // AVOGADRO_QTPLUGINS_BONDING_H

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/openbabel/openbabel.h"


namespace Avogadro::QtPlugins {

class OpenBabelFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit OpenBabelFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new OpenBabel(parent_);
    object->setObjectName("OpenBabel");
    return object;
  }

  QString identifier() const override { return "OpenBabel"; }

  QString description() const override { return "OpenBabel extension"; }

};

} // namespace Avogadro::QtPlugins

#include "OpenBabelPlugin.moc"

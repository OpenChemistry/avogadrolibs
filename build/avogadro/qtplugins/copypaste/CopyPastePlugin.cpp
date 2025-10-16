/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <QtCore/QtPlugin>

#include "/Users/daguila/OSS/avogadrolibs/avogadro/qtplugins/copypaste/copypaste.h"


namespace Avogadro::QtPlugins {

class CopyPasteFactory : public QObject, public QtGui::ExtensionPluginFactory
{
  Q_OBJECT
  Q_PLUGIN_METADATA(IID "org.openchemistry.avogadro.ExtensionPluginFactory")
  Q_INTERFACES(Avogadro::QtGui::ExtensionPluginFactory)

public:
  explicit CopyPasteFactory(QObject* parent_ = nullptr) : QObject(parent_) {}

  QtGui::ExtensionPlugin* createInstance(QObject* parent_ = nullptr) override
  {
    auto* object = new CopyPaste(parent_);
    object->setObjectName("CopyPaste");
    return object;
  }

  QString identifier() const override { return "CopyPaste"; }

  QString description() const override { return "Interact with the clipboard."; }

};

} // namespace Avogadro::QtPlugins

#include "CopyPastePlugin.moc"

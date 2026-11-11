/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "copyasdialog.h"
#include "copypaste.h"

#include <avogadro/io/fileformat.h>
#include <avogadro/qtgui/molecule.h>

#include <gtest/gtest.h>

#include <QtCore/QMimeData>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtGui/QAction>

#include <string>

using Avogadro::QtPlugins::CopyAsDialog;
using Avogadro::QtPlugins::CopyAsFormat;
using Avogadro::QtPlugins::CopyPaste;
using Avogadro::QtPluginsTests::CommandTestHarness;

namespace {

QAction* findAction(const QList<QAction*>& actions, const QString& text)
{
  for (QAction* action : actions)
    if (action->text() == text)
      return action;
  return nullptr;
}

// Methanol from CommandTestHarness::buildMethanol(): C0 O1 H2 H3 H4 H5.
class CopyPasteTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    m_harness.buildMethanol();
    m_plugin.setMolecule(m_harness.molecule());
  }

  CopyPaste m_plugin;
  CommandTestHarness m_harness;
};

} // namespace

TEST_F(CopyPasteTest, copyAsSubmenuHasOtherFormatLast)
{
  const QList<QAction*> actions = m_plugin.actions();
  QAction* other = findAction(actions, QStringLiteral("Other Format…"));
  ASSERT_NE(other, nullptr);
  const QStringList path = m_plugin.menuPath(other);
  ASSERT_EQ(path.size(), 2);
  EXPECT_EQ(path[1], findAction(actions, "SMILES") != nullptr
                       ? m_plugin.menuPath(findAction(actions, "SMILES"))[1]
                       : QString());
  const int otherPriority = other->property("menu priority").toInt();
  for (const char* sibling : { "SMILES", "InChI", "XYZ" }) {
    QAction* action = findAction(actions, sibling);
    ASSERT_NE(action, nullptr) << sibling;
    EXPECT_GT(action->property("menu priority").toInt(), otherPriority)
      << sibling;
  }
}

TEST_F(CopyPasteTest, copyAsFormatsIncludeV3000)
{
  const std::vector<CopyAsFormat> formats = CopyAsDialog::availableFormats();
  QStringList labels;
  for (const CopyAsFormat& f : formats) {
    labels << f.label;
    EXPECT_NE(CopyAsDialog::createFormat(f), nullptr) << f.label.toStdString();
  }
  for (const char* expected :
       { "MDL MOL (V2000)", "MDL MOL (V3000)", "SDF (V2000)", "SDF (V3000)",
         "CML", "CJSON", "XYZ", "SMILES" })
    EXPECT_TRUE(labels.contains(expected)) << expected;
}

// The selection-only copy used to keep nothing but element, position and bond
// order, so a charged or labelled atom came out neutral.
TEST_F(CopyPasteTest, selectionCopyKeepsChargeAndIsotope)
{
  Avogadro::QtGui::Molecule* mol = m_harness.molecule();
  mol->setFormalCharge(1, -1);
  mol->setIsotope(0, 13);
  for (Avogadro::Index i = 0; i < mol->atomCount(); ++i)
    mol->setAtomSelected(i, i < 2); // C0 and O1 only

  QAction* copySmiles = findAction(m_plugin.actions(), "SMILES");
  ASSERT_NE(copySmiles, nullptr);
  copySmiles->trigger();
  const QString text = QGuiApplication::clipboard()->text();
  EXPECT_TRUE(text.contains("[O-]")) << text.toStdString();
  EXPECT_TRUE(text.contains("13")) << text.toStdString();
}

TEST_F(CopyPasteTest, wholeMoleculeCopyUnchanged)
{
  QAction* copyXyz = findAction(m_plugin.actions(), "XYZ");
  ASSERT_NE(copyXyz, nullptr);
  copyXyz->trigger();
  const QString text = QGuiApplication::clipboard()->text();
  EXPECT_EQ(text.section('\n', 0, 0).trimmed(), "6");
}

/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include "commandtestharness.h"

#include "copyasdialog.h"
// copy() is a private slot; the test drives it directly.
#define private public
#include "copypaste.h"
#undef private

#include <avogadro/core/stereo.h>
#include <avogadro/io/fileformat.h>
#include <avogadro/io/mdlformat.h>
#include <avogadro/qtgui/molecule.h>

#include <gtest/gtest.h>

#include <QtCore/QMimeData>
#include <QtGui/QClipboard>
#include <QtGui/QGuiApplication>
#include <QtGui/QAction>

#include <memory>
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
class CopyPasteCommandTest : public ::testing::Test
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

TEST_F(CopyPasteCommandTest, copyAsSubmenuHasOtherFormatLast)
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

TEST_F(CopyPasteCommandTest, copyAsFormatsIncludeV3000)
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
TEST_F(CopyPasteCommandTest, selectionCopyKeepsChargeAndIsotope)
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

TEST_F(CopyPasteCommandTest, wholeMoleculeCopyUnchanged)
{
  QAction* copyXyz = findAction(m_plugin.actions(), "XYZ");
  ASSERT_NE(copyXyz, nullptr);
  copyXyz->trigger();
  const QString text = QGuiApplication::clipboard()->text();
  EXPECT_EQ(text.section('\n', 0, 0).trimmed(), "6");
}

// Stereo-unspecified markers on the selected atoms and bonds must survive the
// selection-only copy, or the clipboard MDL silently turns "either" into a
// defined configuration.
TEST_F(CopyPasteCommandTest, selectionCopyKeepsStereoUnspecified)
{
  Avogadro::QtGui::Molecule* mol = m_harness.molecule();
  mol->clearAtoms();
  // a stray atom first, so the copied indices differ from the originals
  mol->addAtom(8, Avogadro::Vector3(9.0, 9.0, 9.0));
  mol->addAtom(6, Avogadro::Vector3(0.0, 0.0, 0.0));
  mol->addAtom(6, Avogadro::Vector3(1.3, 0.0, 0.0));
  mol->addAtom(6, Avogadro::Vector3(2.0, 1.2, 0.0));
  mol->addBond(1, 2, 2); // bond 0: double, marked
  mol->addBond(2, 3, 1); // bond 1: single, atom 2 marked
  Avogadro::Core::setBondStereoUnspecified(*mol, 0);
  Avogadro::Core::setAtomStereoUnspecified(*mol, 2);
  for (Avogadro::Index i = 0; i < mol->atomCount(); ++i)
    mol->setAtomSelected(i, i > 0);

  for (const char* label : { "MDL MOL (V3000)", "MDL MOL (V2000)" }) {
    std::unique_ptr<Avogadro::Io::FileFormat> format;
    for (const CopyAsFormat& f : CopyAsDialog::availableFormats())
      if (f.label == label)
        format = CopyAsDialog::createFormat(f);
    ASSERT_NE(format, nullptr) << label;

    Avogadro::Io::FileFormat* raw = format.get();
    const bool ok = m_plugin.copy(raw);
    ASSERT_TRUE(ok) << label;

    const std::string text = QGuiApplication::clipboard()->text().toStdString();
    Avogadro::Io::MdlFormat reader;
    Avogadro::QtGui::Molecule back;
    ASSERT_TRUE(reader.readString(text, back)) << label << "\n" << text;
    ASSERT_EQ(back.atomCount(), static_cast<size_t>(3)) << label;
    ASSERT_EQ(back.bondCount(), static_cast<size_t>(2)) << label;
    EXPECT_TRUE(Avogadro::Core::bondStereoUnspecified(back, 0)) << label;
    EXPECT_TRUE(Avogadro::Core::atomStereoUnspecified(back, 1)) << label;
    EXPECT_FALSE(Avogadro::Core::bondStereoUnspecified(back, 1)) << label;
  }
}

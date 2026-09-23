/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/core/molecule.h>
#include <avogadro/io/xyzformat.h>
#include <avogadro/qtgui/backgroundfileformat.h>

#include <QCoreApplication>
#include <QFile>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QThread>

using Avogadro::Core::Molecule;
using Avogadro::Io::XyzFormat;
using Avogadro::QtGui::BackgroundFileFormat;

namespace {

// Ensure a QCoreApplication exists (required for cross-thread signal
// delivery). The test binary uses gtest_main, which does not create one.
QCoreApplication* ensureApp()
{
  if (QCoreApplication::instance())
    return QCoreApplication::instance();
  static int argc = 1;
  static char name[] = "BackgroundFileFormatTest";
  static char* argv[] = { name, nullptr };
  static QCoreApplication app(argc, argv);
  return &app;
}

const char kValidXyz[] = "2\n"
                         "test molecule\n"
                         "H 0.0 0.0 0.0\n"
                         "H 0.0 0.0 0.74\n";

const char kMalformedXyz[] = "not-a-number\n"
                             "garbage\n"
                             "garbage line\n";

QString writeTempFile(QTemporaryDir& dir, const QString& name,
                      const char* content)
{
  QString path = dir.filePath(name);
  QFile f(path);
  bool opened = f.open(QIODevice::WriteOnly | QIODevice::Text);
  EXPECT_TRUE(opened);
  f.write(content);
  f.close();
  return path;
}

} // namespace

class BackgroundFileFormatTest : public ::testing::Test
{};

TEST_F(BackgroundFileFormatTest, Read_ValidXyz_SucceedsAndPopulatesMolecule)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = writeTempFile(dir, "valid.xyz", kValidXyz);

  Molecule mol;
  BackgroundFileFormat bff(new XyzFormat);
  bff.setMolecule(&mol);
  bff.setFileName(path);

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_TRUE(bff.success());
  EXPECT_TRUE(bff.error().isEmpty());
  EXPECT_EQ(mol.atomCount(), 2u);
}

TEST_F(BackgroundFileFormatTest, Read_NoMoleculeSet_ErrorsButStillFinishes)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = writeTempFile(dir, "valid.xyz", kValidXyz);

  BackgroundFileFormat bff(new XyzFormat);
  bff.setFileName(path); // no setMolecule(): a waiting caller must not hang

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_FALSE(bff.success());
  EXPECT_FALSE(bff.error().isEmpty());
}

TEST_F(BackgroundFileFormatTest, Read_NoFormatSet_ErrorsButStillFinishes)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = writeTempFile(dir, "valid.xyz", kValidXyz);

  Molecule mol;
  BackgroundFileFormat bff(nullptr); // no format: destructor must tolerate it
  bff.setMolecule(&mol);
  bff.setFileName(path);

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_FALSE(bff.success());
  EXPECT_FALSE(bff.error().isEmpty());
}

TEST_F(BackgroundFileFormatTest, Read_NoFileNameSet_ErrorsButStillFinishes)
{
  Molecule mol;
  BackgroundFileFormat bff(new XyzFormat);
  bff.setMolecule(&mol); // fileName left empty

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_FALSE(bff.success());
  EXPECT_FALSE(bff.error().isEmpty());
}

TEST_F(BackgroundFileFormatTest, Read_NonexistentFile_FailsCleanly)
{
  Molecule mol;
  BackgroundFileFormat bff(new XyzFormat);
  bff.setMolecule(&mol);
  bff.setFileName(QStringLiteral("/nonexistent/path/does-not-exist.xyz"));

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_FALSE(bff.success());
  EXPECT_FALSE(bff.error().isEmpty());
}

TEST_F(BackgroundFileFormatTest, Read_MalformedFile_FailsCleanlyNoCrash)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = writeTempFile(dir, "malformed.xyz", kMalformedXyz);

  Molecule mol;
  BackgroundFileFormat bff(new XyzFormat);
  bff.setMolecule(&mol);
  bff.setFileName(path);

  QSignalSpy finishedSpy(&bff, &BackgroundFileFormat::finished);
  bff.read();

  EXPECT_EQ(finishedSpy.count(), 1);
  EXPECT_FALSE(bff.success());
  EXPECT_FALSE(bff.error().isEmpty());
}

TEST_F(BackgroundFileFormatTest, Write_ThenReadBack_RoundTrips)
{
  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = dir.filePath("roundtrip.xyz");

  Molecule mol;
  mol.addAtom(1);
  mol.addAtom(1);
  mol.setAtomPosition3d(0, Avogadro::Vector3(0.0, 0.0, 0.0));
  mol.setAtomPosition3d(1, Avogadro::Vector3(0.0, 0.0, 0.74));

  BackgroundFileFormat writer(new XyzFormat);
  writer.setMolecule(&mol);
  writer.setFileName(path);
  QSignalSpy writeSpy(&writer, &BackgroundFileFormat::finished);
  writer.write();
  EXPECT_EQ(writeSpy.count(), 1);
  ASSERT_TRUE(writer.success());

  Molecule readBack;
  BackgroundFileFormat reader(new XyzFormat);
  reader.setMolecule(&readBack);
  reader.setFileName(path);
  QSignalSpy readSpy(&reader, &BackgroundFileFormat::finished);
  reader.read();
  EXPECT_EQ(readSpy.count(), 1);
  ASSERT_TRUE(reader.success());

  EXPECT_EQ(readBack.atomCount(), mol.atomCount());
}

TEST_F(BackgroundFileFormatTest, Read_OnWorkerThread_ViaQueuedInvoke)
{
  ensureApp();

  QTemporaryDir dir;
  ASSERT_TRUE(dir.isValid());
  QString path = writeTempFile(dir, "threaded.xyz", kValidXyz);

  Molecule mol;
  auto* thread = new QThread;
  auto* bff = new BackgroundFileFormat(new XyzFormat);
  bff->setMolecule(&mol);
  bff->setFileName(path);
  bff->moveToThread(thread);
  QObject::connect(thread, &QThread::finished, bff, &QObject::deleteLater);
  thread->start();

  QSignalSpy finishedSpy(bff, &BackgroundFileFormat::finished);
  QMetaObject::invokeMethod(bff, "read", Qt::QueuedConnection);

  ASSERT_TRUE(finishedSpy.wait(5000));

  // The worker thread has returned to its event loop by the time the queued
  // finished() signal is delivered here, so reading bff's state from the
  // main thread is safe.
  EXPECT_TRUE(bff->success());
  EXPECT_EQ(mol.atomCount(), 2u);

  thread->quit();
  ASSERT_TRUE(thread->wait(2000));
  delete thread;
}

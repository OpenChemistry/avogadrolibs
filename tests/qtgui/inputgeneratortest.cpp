/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2013 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include <gtest/gtest.h>

#include "qtguitests.h"

#include <avogadro/molequeue/inputgenerator.h>
#include <avogadro/qtgui/generichighlighter.h>

#include <avogadro/core/molecule.h>

#include <QtCore/QFile>
#include <QtCore/QString>

#include <qjsonarray.h>
#include <qjsonobject.h>

using Avogadro::QtGui::GenericHighlighter;
using Avogadro::MoleQueue::InputGenerator;

TEST(InputGeneratorTest, exercise)
{
  QString scriptFilePath(AVOGADRO_DATA
                         "/tests/avogadro/scripts/inputgeneratortest.py");
  InputGenerator gen(scriptFilePath);

  EXPECT_TRUE(gen.scriptFilePath() == scriptFilePath);

  EXPECT_TRUE(gen.displayName() == QLatin1String("Input Generator Test"))
    << gen.errorList().join("\n").toStdString(); // catch syntax errors

  const QJsonObject genOptions(gen.options());
  EXPECT_TRUE(genOptions["userOptions"].isObject());
  QJsonObject userOptions(genOptions["userOptions"].toObject());
  EXPECT_TRUE(userOptions["Basis"].isObject());

  // Create a set of input options by setting defaults
  QJsonObject inputOptions;
  QJsonObject options;
  foreach (const QString& optionName, userOptions.keys()) {
    EXPECT_TRUE(userOptions[optionName].isObject());
    QJsonObject option(userOptions[optionName].toObject());
    QString optionType(option["type"].toString());
    if (optionType == QLatin1String("stringList")) {
      QJsonArray strings(option["values"].toArray());
      int index = static_cast<int>(options["default"].toDouble());
      options.insert(optionName, strings.at(index));
    } else {
      options.insert(optionName, option["default"]);
    }
  }

  // Use a cml file from the test data to test file path handling.
  QString testFilePath(AVOGADRO_DATA "/data/ethane.cml");
  options["Test FilePath"] = testFilePath;

  // And a fake molecule...
  Avogadro::Core::Molecule mol;
  mol.addAtom(6).setPosition3d(Avogadro::Vector3(1, 1, 1));
  mol.addAtom(1).setPosition3d(Avogadro::Vector3(2, 3, 4));
  mol.addAtom(8).setPosition3d(Avogadro::Vector3(-2, 3, -4));

  inputOptions.insert("options", options);

  // Adding debugging should add another file:
  gen.setDebug(false);
  EXPECT_TRUE(gen.generateInput(inputOptions, mol));
  int numFilesNoDebug(gen.numberOfInputFiles());
  gen.setDebug(true);
  EXPECT_TRUE(gen.debug());
  EXPECT_TRUE(gen.generateInput(inputOptions, mol));
  EXPECT_EQ(numFilesNoDebug + 1, gen.numberOfInputFiles());

  // Check that all expected files are produced
  EXPECT_EQ(4, gen.numberOfInputFiles());
  EXPECT_TRUE(gen.fileNames().contains("job.opts"));
  EXPECT_TRUE(gen.fileNames().contains("job.coords"));
  EXPECT_TRUE(gen.fileNames().contains("job.testFilePath"));
  EXPECT_TRUE(gen.fileNames().contains("debug_info"));
  EXPECT_EQ(gen.mainFileName().toStdString(), std::string("job.opts"));

  // Validate the coordinates
  QString coords(gen.fileContents("job.coords"));
  EXPECT_TRUE(
    coords.contains("C      1.000000 0    1.000000 1    1.000000 1 Carbon"));
  EXPECT_TRUE(
    coords.contains("H      2.000000 0    3.000000 1    4.000000 1 Hydrogen"));
  EXPECT_TRUE(
    coords.contains("O     -2.000000 0    3.000000 1   -4.000000 1 Oxygen"));

  // Validate the file returned by path
  QFile testFile(testFilePath);
  EXPECT_TRUE(testFile.open(QFile::ReadOnly));
  QByteArray refData(testFile.readAll());
  EXPECT_EQ(std::string(refData.constData()),
            gen.fileContents("job.testFilePath").toStdString());

  // Check warnings/errors
  EXPECT_FALSE(gen.hasErrors());
  EXPECT_EQ(0, gen.errorList().size());
  EXPECT_EQ(5, gen.warningList().size());

  // Highlight styles:
  GenericHighlighter* highlighter(gen.createFileHighlighter("job.opts"));
  EXPECT_TRUE(highlighter != nullptr);
  delete highlighter;
  highlighter = gen.createFileHighlighter("debug_info");
  EXPECT_TRUE(highlighter == nullptr);
  delete highlighter;
}

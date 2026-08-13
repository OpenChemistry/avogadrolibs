/******************************************************************************
  This source file is part of the Avogadro project.
  This source code is released under the 3-Clause BSD License, (see "LICENSE").
******************************************************************************/

#include <gtest/gtest.h>

#include <avogadro/qtgui/pythonscript.h>

#include <QtCore/QJsonObject>
#include <QtCore/QList>

using Avogadro::QtGui::PythonScript;

TEST(ScriptProgressTest, ParsesEnvelope)
{
  QJsonObject payload;
  const QByteArray line(
    R"({"avogadro": {"message": "Conformer 3 of 25", "value": 3,)"
    R"( "maximum": 25}})");

  ASSERT_TRUE(PythonScript::parseProgressEnvelope(line, payload));
  EXPECT_EQ(payload.value("message").toString(), QString("Conformer 3 of 25"));
  EXPECT_EQ(payload.value("value").toInt(-1), 3);
  EXPECT_EQ(payload.value("maximum").toInt(-1), 25);
}

TEST(ScriptProgressTest, ParsesPartialEnvelope)
{
  QJsonObject payload;

  // A message on its own is valid; absent members stay absent.
  ASSERT_TRUE(PythonScript::parseProgressEnvelope(
    R"({"avogadro": {"message": "Writing results"}})", payload));
  EXPECT_EQ(payload.value("message").toString(), QString("Writing results"));
  EXPECT_EQ(payload.value("value").toInt(-1), -1);
  EXPECT_EQ(payload.value("maximum").toInt(-1), -1);

  // So is an empty payload.
  EXPECT_TRUE(
    PythonScript::parseProgressEnvelope(R"({"avogadro": {}})", payload));
}

TEST(ScriptProgressTest, IgnoresSurroundingWhitespace)
{
  QJsonObject payload;

  // Windows line endings leave a stray carriage return on the line.
  EXPECT_TRUE(PythonScript::parseProgressEnvelope(
    "  {\"avogadro\": {\"value\": 1, \"maximum\": 2}}\r", payload));
  EXPECT_EQ(payload.value("value").toInt(-1), 1);
}

TEST(ScriptProgressTest, RejectsNonEnvelopes)
{
  QJsonObject payload;

  // Plain output from a script.
  EXPECT_FALSE(PythonScript::parseProgressEnvelope("Starting up...", payload));
  EXPECT_FALSE(PythonScript::parseProgressEnvelope(QByteArray(), payload));

  // Valid JSON, but not an envelope.
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"({"message": "hello"})", payload));
  EXPECT_FALSE(PythonScript::parseProgressEnvelope(R"(["avogadro"])", payload));

  // An "avogadro" member alongside others is a result, not an envelope.
  EXPECT_FALSE(PythonScript::parseProgressEnvelope(
    R"({"avogadro": {"value": 1}, "cjson": {}})", payload));

  // The "avogadro" member has to be an object. A scalar or null would parse
  // into an empty payload, so the line would vanish from the output while
  // reporting progress nobody asked for.
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"({"avogadro": 1})", payload));
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"({"avogadro": null})", payload));
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"({"avogadro": "text"})", payload));
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"({"avogadro": []})", payload));

  // Truncated JSON must not be mistaken for an envelope.
  EXPECT_FALSE(PythonScript::parseProgressEnvelope(
    R"({"avogadro": {"value": 1})", payload));

  // A pretty-printed result mentioning "avogadro" arrives one line at a time,
  // and no individual line parses as a complete object.
  EXPECT_FALSE(PythonScript::parseProgressEnvelope("{", payload));
  EXPECT_FALSE(
    PythonScript::parseProgressEnvelope(R"(  "avogadro": {)", payload));
}

TEST(ScriptProgressTest, FiltersProgressFromOutput)
{
  QByteArray buffer("Loading model...\n"
                    R"({"avogadro": {"value": 1, "maximum": 2}})"
                    "\n"
                    R"({"avogadro": {"message": "Done"}})"
                    "\n"
                    R"({"avogadro": 1})"
                    "\n"
                    "{\n"
                    "  \"cjson\": {}\n"
                    "}\n");
  QByteArray output;
  QList<QJsonObject> payloads;

  PythonScript::filterProgressLines(buffer, output, payloads);

  EXPECT_TRUE(buffer.isEmpty()); // no partial line left over
  ASSERT_EQ(payloads.size(), 2);
  EXPECT_EQ(payloads.at(0).value("value").toInt(-1), 1);
  EXPECT_EQ(payloads.at(1).value("message").toString(), QString("Done"));

  // Everything else survives byte for byte, newlines included - including the
  // scalar "avogadro" line, which is not an envelope.
  EXPECT_EQ(output, QByteArray("Loading model...\n{\"avogadro\": 1}\n"
                               "{\n  \"cjson\": {}\n}\n"));
}

TEST(ScriptProgressTest, BuffersPartialLines)
{
  QByteArray buffer;
  QByteArray output;
  QList<QJsonObject> payloads;

  // An envelope split across two reads is not acted on until it is complete.
  buffer += R"({"avogadro": {"value")";
  PythonScript::filterProgressLines(buffer, output, payloads);
  EXPECT_TRUE(payloads.isEmpty());
  EXPECT_TRUE(output.isEmpty());

  buffer += ": 7}}\nresult";
  PythonScript::filterProgressLines(buffer, output, payloads);
  ASSERT_EQ(payloads.size(), 1);
  EXPECT_EQ(payloads.at(0).value("value").toInt(-1), 7);

  // The unterminated final line stays buffered rather than being emitted.
  EXPECT_TRUE(output.isEmpty());
  EXPECT_EQ(buffer, QByteArray("result"));
}

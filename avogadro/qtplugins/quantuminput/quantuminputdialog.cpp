/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2012 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "quantuminputdialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>
#include <avogadro/io/cjsonformat.h>
#include <avogadro/io/cmlformat.h>
#include <avogadro/qtgui/molecule.h>

#include <molequeue/client/client.h>
#include <molequeue/client/job.h>

#include <qjsonarray.h>
#include <qjsondocument.h>
#include <qjsonobject.h>
#include <qjsonvalue.h>

#include <QtGui/QFileDialog>
#include <QtGui/QFormLayout>
#include <QtGui/QHBoxLayout>
#include <QtGui/QMessageBox>
#include <QtGui/QProgressDialog>

#include <QtCore/QDebug>
#include <QtCore/QFile>
#include <QtCore/QProcess>
#include <QtCore/QRegExp>
#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtCore/QTimer>

namespace Avogadro {
namespace QtPlugins {

QuantumInputDialog::QuantumInputDialog(const QString &script, QWidget *parent_,
                                       Qt::WindowFlags f)
  : QDialog( parent_, f ),
    m_molecule(NULL),
    m_client(new MoleQueue::Client(this)),
    m_updatePending(false),
    m_scriptFilePath(script),
    m_inputMoleculeFormat(NoInputFormat)
{
  m_ui.setupUi(this);

  updateOptions();

  connectButtons();
  connectMoleQueue();

  updatePreviewText();

  m_client->connectToServer();
  if (m_client->isConnected())
    m_client->requestQueueList();
}

QuantumInputDialog::~QuantumInputDialog()
{
}

void QuantumInputDialog::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule) {
    return;
  }
  else if (m_molecule) {
    disconnect(this, SLOT(updatePreviewText()));
  }

  m_molecule = mol;

  connect(mol, SIGNAL(changed(unsigned int)), SLOT(updatePreviewText()));

  updatePreviewText();
}

void QuantumInputDialog::updatePreviewText()
{
  if (m_updatePending)
    return;

  m_updatePending = true;
  QTimer::singleShot(250, this, SLOT(updatePreviewTextImmediately()));
}

void QuantumInputDialog::updatePreviewTextImmediately()
{
  m_updatePending = false;
  QProcess proc(this);
  proc.setProcessChannelMode(QProcess::MergedChannels);

  QStringList args;
  args << "--generate-input" << collectOptions();

  /// @todo Debugging..
//  args << "--debug";

  switch (m_inputMoleculeFormat) {
  case NoInputFormat:
  default:
    break;
  case CJSON:
    args << "--cjson" << generateCJson();
    break;
  }

  /// @todo FIXME: What if python is not in the path (e.g. windows) or uses an
  /// odd executable name (e.g. "python2" on arch linux)? Similar concerns with
  /// java scripts...
  proc.start(m_scriptFilePath, args);
  if (!proc.waitForFinished(3000)) {
    qWarning() << tr("Error retrieving input generator options.");
    return;
  }

  QByteArray json = proc.readAll();

  QJsonParseError error;
  QJsonDocument doc = QJsonDocument::fromJson(json, &error);
  /// @todo Error handling!

  /// @todo multifile support. Just picking 'job.inp' for now.
  QString text;
  if (doc.object()["files"].toArray().first().toObject()["job.inp"].isString()) {
    text = doc.object()["files"].toArray().first().toObject()["job.inp"].toString();
    replaceKeywords(text);
  }
  else
    text = json;

  m_ui.previewText->setText(text);
}

void QuantumInputDialog::refreshPrograms()
{
  if (!m_client->isConnected()) {
    m_client->connectToServer();
    if (!m_client->isConnected()) {
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }
  }
  m_client->requestQueueList();
}

void QuantumInputDialog::queueListReceived(const QJsonObject &queueList)
{
  m_ui.programCombo->clear();
  int firstGamess = -1;
  foreach (const QString &queue, queueList.keys())
    {
    foreach (const QJsonValue &program, queueList.value(queue).toArray())
    {
      if (program.isString()) {
        if (firstGamess < 0 && program.toString().contains("GAMESS"))
          firstGamess = m_ui.programCombo->count();
        m_ui.programCombo->addItem(QString("%1 (%2)").arg(program.toString(),
                                                        queue));
      }
    }
  }
  m_ui.programCombo->setCurrentIndex(firstGamess);
}


void QuantumInputDialog::defaultsClicked()
{
  setOptionDefaults();
  updatePreviewText();
}

void QuantumInputDialog::generateClicked()
{
  QString filename =
      QFileDialog::getSaveFileName(this, tr("Save input file"));

  // User cancel:
  if (filename.isNull())
    return;

  QFile file(filename);
  bool success = false;
  if (file.open(QFile::WriteOnly | QFile::Text)) {
    if (file.write(m_ui.previewText->toPlainText().toLatin1()) > 0) {
      success = true;
    }
    file.close();
  }

  if (!success) {
    QMessageBox::critical(this, tr("Output Error"),
                          tr("Failed to write to file %1.").arg(filename));
  }
}

void QuantumInputDialog::computeClicked()
{
  if (!m_client->isConnected()) {
    m_client->connectToServer();
    if (!m_client->isConnected()) {
      QMessageBox::information(this, tr("Cannot connect to MoleQueue"),
                               tr("Cannot connect to MoleQueue server. Please "
                                  "ensure that it is running and try again."));
      return;
    }
  }

  QString programText = m_ui.programCombo->currentText();
  if (programText.isEmpty()) {
    QMessageBox::information(this, tr("No program set."),
                             tr("Cannot determine which MoleQueue program "
                                "configuration to use. Has MoleQueue been "
                                "configured?"));
    return;
  }

  QRegExp parser("^(.+) \\((.+)\\)$");
  int parseResult = parser.indexIn(programText);

  // Should not happen...
  if (parseResult == -1)
    return;

  const QString program = parser.cap(1);
  const QString queue = parser.cap(2);

  MoleQueue::JobObject job;
  job.setQueue(queue);
  job.setProgram(program);
  job.setDescription(tr("Avogadro calculation"));
  job.setValue("numberOfCores", m_ui.coresSpinBox->value());
  job.setInputFile("job.inp", m_ui.previewText->toPlainText());

  m_client->submitJob(job);
}

void QuantumInputDialog::connectButtons()
{
  connect( m_ui.defaultsButton, SIGNAL(clicked()), SLOT(defaultsClicked()));
  connect( m_ui.generateButton, SIGNAL(clicked()), SLOT(generateClicked()));
  connect( m_ui.computeButton, SIGNAL(clicked()), SLOT(computeClicked()));
  connect( m_ui.closeButton, SIGNAL(clicked()), SLOT(close()));
  connect( m_ui.refreshProgramsButton, SIGNAL(clicked()),
           SLOT(refreshPrograms()));
}

void QuantumInputDialog::connectMoleQueue()
{
  connect(m_client, SIGNAL(queueListReceived(QJsonObject)),
          this, SLOT(queueListReceived(QJsonObject)));
}

void QuantumInputDialog::updateOptions()
{
  QProcess proc(this);
  proc.setProcessChannelMode(QProcess::MergedChannels);
  /// @todo See other TODO near QProcess::start() above, re: exec details.
  proc.start(m_scriptFilePath, QStringList() << "--print-options");
  if (!proc.waitForFinished(3000)) {
    qWarning() << tr("Error retrieving input generator options.");
    return;
  }

  QByteArray optString = proc.readAll();
  QJsonParseError error;
  QJsonDocument doc = QJsonDocument::fromJson(optString, &error);
  if (error.error != QJsonParseError::NoError) {
    qWarning() << tr("Error parsing input generator options. Input:\n\n"
                     "%1\n\nError: %1 (at offset %2) Raw data:%3\n")
                  .arg(error.errorString()).arg(error.offset)
                  .arg(optString.constData());
    return;
  }

  if (!doc.isObject()) {
    qWarning() << tr("Error parsing input generator options. Input:\n\n"
                     "%1\n\nError: Not a JSON object.")
                  .arg(error.errorString()).arg(error.offset);
    return;
  }

  m_options = doc.object();

  // Create the widgets, etc for the gui
  buildOptionGui();

  // Update generator options
  updateInputMoleculeFormat();

  setOptionDefaults();
}

void QuantumInputDialog::buildOptionGui()
{
  // Clear old widgets from the layout
  m_widgets.clear();
  delete m_ui.optionsWidget->layout();
  QFormLayout *form = new QFormLayout;
  m_ui.optionsWidget->setLayout(form);

  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    return;
  }

  QJsonObject userOptions = m_options["userOptions"].toObject();

  // Calculation Type at the top:
  if (userOptions.contains("Calculation Type"))
    addOptionRow(tr("Calculation Type"), userOptions.take("Calculation Type"));

  // Theory/basis next. Combine into one row if both present.
  bool hasTheory = userOptions.contains("Theory");
  bool hasBasis = userOptions.contains("Basis");
  if (hasTheory && hasBasis) {
    QWidget *theoryWidget = createOptionWidget(userOptions.take("Theory"));
    QWidget *basisWidget = createOptionWidget(userOptions.take("Basis"));
    QHBoxLayout *hbox = new QHBoxLayout;
    if (theoryWidget) {
      hbox->addWidget(theoryWidget);
      m_widgets.insert("Theory", theoryWidget);
    }
    if (basisWidget) {
      hbox->addWidget(basisWidget);
      m_widgets.insert("Basis", basisWidget);
    }
    hbox->addStretch();

    form->addRow(tr("Theory:"), hbox);
  }
  else {
    if (hasTheory)
      addOptionRow(tr("Theory"), userOptions["Theory"]);
    if (hasBasis)
      addOptionRow(tr("Basis"), userOptions["Basis"]);
  }

  // Other special cases:
  if (userOptions.contains("Charge"))
    addOptionRow(tr("Charge"), userOptions.take("Charge"));
  if (userOptions.contains("Multiplicity"))
    addOptionRow(tr("Multiplicity"), userOptions.take("Multiplicity"));

  // Add remaining keys.
  for (QJsonObject::const_iterator it = userOptions.constBegin(),
       itEnd = userOptions.constEnd(); it != itEnd; ++it) {
    addOptionRow(it.key(), it.value());
  }
}

void QuantumInputDialog::addOptionRow(const QString &label,
                                      const QJsonValue &option)
{
  QWidget *widget = createOptionWidget(option);
  if (!widget)
    return;

  QFormLayout *form = qobject_cast<QFormLayout*>(m_ui.optionsWidget->layout());
  if (!form) {
    qWarning() << "Cannot add option" << label
               << "to GUI -- layout is not a form.";
    widget->deleteLater();
    return;
  }
  form->addRow(label + ":", widget);
  m_widgets.insert(label, widget);
}

QWidget* QuantumInputDialog::createOptionWidget(const QJsonValue &option)
{
  /// @todo Expand this to cover clamped number ranges, strings, etc
  if (!option.isObject())
    return NULL;

  QJsonObject obj = option.toObject();

  if (!obj.contains("values") || !obj["values"].isArray())
    return NULL;

  QJsonArray valueArray = obj["values"].toArray();

  QComboBox *combo = new QComboBox;

  for (QJsonArray::const_iterator vit = valueArray.constBegin(),
       vitEnd = valueArray.constEnd(); vit != vitEnd; ++vit) {
    combo->addItem((*vit).toString());
  }
  connect(combo, SIGNAL(currentIndexChanged(int)), SLOT(updatePreviewText()));

  return combo;
}

void QuantumInputDialog::updateInputMoleculeFormat()
{
  /// @todo Document this option
  m_inputMoleculeFormat = NoInputFormat;

  if (m_options.contains("inputMoleculeFormat") &&
      m_options["inputMoleculeFormat"].isString()) {
    QString format = m_options["inputMoleculeFormat"].toString();
    if (format == "cjson")
      m_inputMoleculeFormat = CJSON;
  }
}

void QuantumInputDialog::setOptionDefaults()
{
  if (!m_options.contains("userOptions") ||
      !m_options["userOptions"].isObject()) {
    return;
  }

  QJsonObject userOptions = m_options["userOptions"].toObject();

  for (QJsonObject::ConstIterator it = userOptions.constBegin(),
       itEnd = userOptions.constEnd(); it != itEnd; ++it) {
    QString label = it.key();
    QJsonValue val = it.value();

    if (!val.isObject()) {
      qWarning() << tr("Error: value must be object for key '%1'.")
                    .arg(label);
      continue;
    }

    QJsonObject obj = val.toObject();

    int def = 0;
    if (obj["default"].isDouble()) {
      def = static_cast<int>(std::floor(obj["default"].toDouble() + 0.5));
    }

    if (QComboBox *combo = qobject_cast<QComboBox*>(m_widgets.value(label, NULL)))
      combo->setCurrentIndex(def);
  }
}

QByteArray QuantumInputDialog::collectOptions() const
{
  QJsonObject ret;

  foreach (QString label, m_widgets.keys())
    if (QComboBox *combo = qobject_cast<QComboBox*>(m_widgets.value(label, NULL)))
      ret.insert(label, combo->currentText());

  return QJsonDocument(ret).toJson();
}

QByteArray QuantumInputDialog::generateCJson() const
{
  if (!m_molecule)
    return "";

  std::string ret;

  Io::CjsonFormat cjson;
  cjson.writeString(ret, *m_molecule);

  return QByteArray(ret.c_str());
}

QString QuantumInputDialog::generateCoordinateBlock(const QString &spec) const
{
  if (!m_molecule)
    return "";

  // @todo Document these
  // Coordinate blocks:
  // $$coords:<spec>$$ where <spec> is a character string indicating the
  // atom attributes to print:
  // - 'Z': Atomic number
  // - 'S': Element symbol
  // - 'N': Element name
  // - 'x': x coordinate
  // - 'y': y coordinate
  // - 'z': z coordinate
  bool needElementSymbol = spec.contains('S');
  bool needElementName = spec.contains('N');
  bool needPosition =
      spec.contains('x') || spec.contains('y') || spec.contains('z');

  // Loop variables
  size_t numAtoms = m_molecule->atomCount();
  Core::Atom atom;
  unsigned char atomicNumber;
  const char *symbol;
  const char *name;
  Vector3 pos3d;
  QString::const_iterator it;
  QString::const_iterator begin = spec.constBegin();
  QString::const_iterator end = spec.constEnd();

  // The replacement string and text stream
  QString replacement;
  QTextStream stream(&replacement);
  stream.setRealNumberNotation(QTextStream::FixedNotation);
  stream.setRealNumberPrecision(6);
  // Field width for real numbers:
  const int realWidth = 11;

  // Generate the replacement block
  for (size_t atom_i = 0; atom_i < numAtoms; ++atom_i) {
    atom = m_molecule->atom(atom_i);
    atomicNumber = atom.atomicNumber();
    if (needElementSymbol)
      symbol = Core::Elements::symbol(atomicNumber);
    if (needElementName)
      name = Core::Elements::name(atomicNumber);
    if (needPosition)
      pos3d = atom.position3d();

    it = begin;
    while (it != end) {
      switch (it->toLatin1()) {
      case 'Z':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(3);
        stream << static_cast<int>(atomicNumber);
        break;
      case 'S':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(3);
        stream << symbol;
        break;
      case 'N':
        stream.setFieldAlignment(QTextStream::AlignLeft);
        stream.setFieldWidth(13); // longest name is currently 13 char
        stream << name;
        break;
      case 'x':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.x();
        break;
      case 'y':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.y();
        break;
      case 'z':
        stream.setFieldAlignment(QTextStream::AlignRight);
        stream.setFieldWidth(realWidth);
        stream << pos3d.z();
        break;
      } // end switch

      stream << (++it != end ? " " : "\n");
    } // end while
  } // end for atom

  // Remove the final newline
  replacement.chop(1);
  return replacement;
}

void QuantumInputDialog::replaceKeywords(QString &str) const
{
  if (!m_molecule)
    return;

  // Find each coordinate block keyword in the file, then generate and replace
  // it with the appropriate values.
  QRegExp coordParser("\\$\\$coords:([^\\$]*)\\$\\$");
  int ind = 0;
  while ((ind = coordParser.indexIn(str, ind)) != -1) {
    // Extract spec and prepare the replacement
    const QString keyword = coordParser.cap(0);
    const QString spec = coordParser.cap(1);

    // Replace all blocks with this signature
    str.replace(keyword, generateCoordinateBlock(spec));

  } // end for coordinate block
}

} // end namespace QtPlugins
} // end namespace Avogadro

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

#include "cartesianeditordialog.h"
#include "ui_cartesianeditordialog.h"
#include "cartesiantextedit.h"

#include <avogadro/qtgui/molecule.h>

#include <avogadro/core/avogadrocore.h>
#include <avogadro/core/coordinateblockgenerator.h>
#include <avogadro/core/elements.h>
#include <avogadro/core/vector.h>

#include <QtGui/QApplication>
#include <QtGui/QClipboard>
#include <QtGui/QFont>
#include <QtGui/QIcon>
#include <QtGui/QMessageBox>
#include <QtGui/QTextCursor>
#include <QtGui/QTextDocument>
#include <QtGui/QToolTip>
#include <QtGui/QRegExpValidator>

#include <QtCore/QDebug>
#include <QtCore/QMimeData>
#include <QtCore/QMutableListIterator>
#include <QtCore/QRegExp>
#include <QtCore/QString>
#include <QtCore/QTimer>

// Define this to print out details of the format detection algorithm.
#undef ENABLE_FORMAT_DEBUG

#ifdef ENABLE_FORMAT_DEBUG
#define FORMAT_DEBUG(x) x
#else // ENABLE_FORMAT_DEBUG
#define FORMAT_DEBUG(x)
#endif // ENABLE_FORMAT_DEBUG

using Avogadro::QtGui::Molecule;
using Avogadro::Core::Atom;
using Avogadro::Core::Elements;
using Avogadro::Vector3;

namespace {

// Ensure a cross-platform monospaced font
#ifdef Q_WS_X11
static const QString EDITOR_FONT = "Monospace";
#else // Windows and Mac
static const QString EDITOR_FONT = "Courier";
#endif

// Various integer constants
enum {
  CustomPreset = 0
};

// Distance unit indices -- keep in sync with the .ui file.
enum DistanceUnitIndex {
  Angstrom = 0,
  Bohr
};

// Some frequently used regexes:
static const QRegExp TOKEN_SEPARATOR("[\\s,;]+");
static const QRegExp VALID_TOKEN("[^\\s,;]+");
static const QRegExp INT_CHECKER("(:?[+-])?\\d+");
static const QRegExp DOUBLE_CHECKER(
    "(:?[+-])?"                   // Leading sign
    "(:?"                         // Must match one of the following:
    "\\d*\\.\\d*"                 // Fractional part
    "|"                           // or
    "\\d+[EeDd](:?[+-])?\\d+"     // Exponential part
    "|"                           // or
    "\\d*\\.\\d*"                 // Fractional part and
    "[EeDd](:?[+-])?\\d+"         // Exponential part
    ")");

struct AtomStruct {
  unsigned char atomicNumber;
  Vector3 pos;
};

} // end anon namespace

namespace Avogadro {
namespace QtPlugins {

// Storage class used to hold state while validating input.
class CartesianEditorDialog::ValidateStorage
{
public:
  ValidateStorage()
    : isValidating(false),
      restartWhenFinished(false),
      collectAtoms(false),
      convertDistance(false),
      distanceConversion(1.f)
  {}

  bool isValidating;
  bool restartWhenFinished;
  bool collectAtoms;
  bool convertDistance;
  float distanceConversion;

  // Format specification
  QString spec;

  // Text cursors
  QTextCursor lineCursor;
  QTextCursor tokenCursor;

  // Accumulate atom data
  QVector<AtomStruct> atoms;
};

CartesianEditorDialog::CartesianEditorDialog(QWidget *parent_) :
  QDialog(parent_),
  m_ui(new Ui::CartesianEditorDialog),
  m_molecule(NULL),
  m_validate(new ValidateStorage),
  m_defaultSpec("SZxyz#N")
{
  m_ui->setupUi(this);

  // Set up text editor
  m_ui->text->setFont(QFont(EDITOR_FONT, qApp->font().pointSize()));

  // Setup spec edit
  QRegExp specRegExp("[#ZGSNxyz01_]*");
  QRegExpValidator *specValidator = new QRegExpValidator(specRegExp, this);
  m_ui->spec->setValidator(specValidator);
  connect(m_ui->presets, SIGNAL(currentIndexChanged(int)),
          SLOT(presetChanged(int)));
  connect(m_ui->spec, SIGNAL(textChanged(QString)), SLOT(specChanged()));
  connect(m_ui->spec, SIGNAL(textEdited(QString)), SLOT(specEdited()));

  connect(m_ui->distanceUnit, SIGNAL(currentIndexChanged(int)),
          SLOT(updateText()));

  connect(m_ui->help,   SIGNAL(clicked()), SLOT(helpClicked()));
  connect(m_ui->cut,    SIGNAL(clicked()), SLOT(cutClicked()));
  connect(m_ui->copy,   SIGNAL(clicked()), SLOT(copyClicked()));
  connect(m_ui->paste,  SIGNAL(clicked()), SLOT(pasteClicked()));
  connect(m_ui->revert, SIGNAL(clicked()), SLOT(revertClicked()));
  connect(m_ui->clear,  SIGNAL(clicked()), SLOT(clearClicked()));
  connect(m_ui->apply,  SIGNAL(clicked()), SLOT(applyClicked()));

  m_ui->cut->setIcon(QIcon::fromTheme("edit-cut")); /// @todo Fallback icon
  m_ui->copy->setIcon(QIcon::fromTheme("edit-copy")); /// @todo Fallback icon
  m_ui->paste->setIcon(QIcon::fromTheme("edit-paste")); /// @todo Fallback icon

  buildPresets();
  listenForTextEditChanges(true);
}

CartesianEditorDialog::~CartesianEditorDialog()
{
  delete m_ui;
}

void CartesianEditorDialog::setMolecule(QtGui::Molecule *mol)
{
  if (mol != m_molecule) {
    if (m_molecule)
      m_molecule->disconnect(this);
    m_molecule = mol;
    connect(m_molecule, SIGNAL(changed(uint)), SLOT(moleculeChanged(uint)));
    updateText();
  }
}

void CartesianEditorDialog::moleculeChanged(uint change)
{
  if (static_cast<Molecule::MoleculeChange>(change) & Molecule::Atoms)
    updateText();
}

void CartesianEditorDialog::presetChanged(int ind)
{
  QVariant itemData(m_ui->presets->itemData(ind));
  bool isCustom(itemData.type() != QVariant::String);

  // Changing the spec text will update the editor text.
  m_ui->spec->setText(isCustom ? m_defaultSpec
                               : itemData.toString());
}

void CartesianEditorDialog::specChanged()
{
  // Store the spec if custom preset is selected.
  if (m_ui->presets->currentIndex() == CustomPreset)
    m_defaultSpec = m_ui->spec->text();
  updateText();
}

void CartesianEditorDialog::specEdited()
{
  // Editing the spec switches to and updates the custom preset.
  if (m_ui->presets->currentIndex() != CustomPreset) {
    m_defaultSpec = m_ui->spec->text();
    m_ui->presets->setCurrentIndex(CustomPreset);
  }
}

void CartesianEditorDialog::updateText()
{
  if (m_ui->text->document()->isModified()) {
    int reply =
        QMessageBox::question(this, tr("Overwrite changes?"),
                              tr("The text document has been modified. Would "
                                 "you like to discard your changes and revert "
                                 "to the current molecule?"),
                          QMessageBox::Yes | QMessageBox::No,
                          QMessageBox::No);
    if (reply != QMessageBox::Yes)
      return;
  }

  Core::CoordinateBlockGenerator gen;
  gen.setMolecule(m_molecule);
  gen.setSpecification(m_ui->spec->text().toStdString());
  switch (m_ui->distanceUnit->currentIndex()) {
  default:
  case Angstrom:
    gen.setDistanceUnit(Core::CoordinateBlockGenerator::Angstrom);
    break;
  case Bohr:
    gen.setDistanceUnit(Core::CoordinateBlockGenerator::Bohr);
    break;
  }

  // Disable markup for the generated text.
  listenForTextEditChanges(false);
  m_ui->text->document()->setPlainText(
        QString::fromStdString(gen.generateCoordinateBlock()));
  listenForTextEditChanges(true);
  m_ui->text->document()->setModified(false);
}

void CartesianEditorDialog::helpClicked()
{
  // Give the spec lineedit focus and show its tooltip.
  m_ui->spec->setFocus(Qt::MouseFocusReason);
  QPoint point(m_ui->spec->pos() + pos());
  point.setY(point.y() + m_ui->spec->frameGeometry().height() + 5);
  QToolTip::showText(point, m_ui->spec->toolTip(), m_ui->spec);
}

void CartesianEditorDialog::validateInput()
{
  if (m_validate->isValidating) {
    m_validate->restartWhenFinished = true;
    return;
  }

  // No text, nothing to do!
  if (m_ui->text->document()->isEmpty()) {
    emit validationFinished(true);
    return;
  }

  // Try to detect the input format
  QString inputFormat(detectInputFormat());
  if (inputFormat.isEmpty()) {
    emit validationFinished(false);
    return;
  }

  // Reset formatting. Stop listening for changes since format changes will
  // retrigger validation.
  listenForTextEditChanges(false);
  m_ui->text->resetMarks();
  listenForTextEditChanges(true);

  // Initialize
  m_validate->isValidating = true;
  m_validate->spec = inputFormat;
  m_validate->lineCursor = QTextCursor(m_ui->text->document());

  // Start the worker
  validateInputWorker();
}

void CartesianEditorDialog::validateInputWorker()
{
  if (!m_validate->isValidating)
    return;

  // Disable revalidation due to formatting changes.
  listenForTextEditChanges(false);

  // Setup some aliases to keep code concise:
  const QString &spec(m_validate->spec);
  QTextCursor &lineCursor(m_validate->lineCursor);
  QTextCursor &tokenCursor(m_validate->tokenCursor);

  QTextDocument *doc(m_ui->text->document());
  QString::const_iterator begin(spec.constBegin());
  QString::const_iterator end(spec.constEnd());
  QString::const_iterator iter;

  // Only do a few lines at a time, then return control to the event loop.
  int lineThisIteration = 0;

  while (++lineThisIteration <= 10 && !lineCursor.atEnd()) {
    // Place the entire line in the line cursor's selection.
    lineCursor.movePosition(QTextCursor::StartOfLine, QTextCursor::MoveAnchor);
    lineCursor.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);

    // Start the token cursor at the beginning of the current line.
    tokenCursor.setPosition(lineCursor.anchor(), QTextCursor::MoveAnchor);

    // This is used when applying changes to store the atom specifications.
    AtomStruct atom;

    // Iterate through spec characters
    for (iter = begin; iter != end; ++iter) {
      // Place the next valid token in tokenCursor's selection:
      tokenCursor = doc->find(VALID_TOKEN, tokenCursor);

      // If the token cursor has moved off of the current line, mark the entire
      // line as invalid and move on.
      if (tokenCursor.isNull()
          || tokenCursor.position() > lineCursor.position()) {
        m_ui->text->markInvalid(lineCursor, tr("Too few entries on line."));
        break;
      }

      switch (iter->toLatin1()) {
      case '?': // Nothing to validate other than that this is a valid token.
        break;

      case 'N': {
        // Validate name:
        QString cleanToken(tokenCursor.selectedText().toLower());
        if (!cleanToken.isEmpty())
          cleanToken.replace(0, 1, cleanToken[0].toUpper());
        std::string tokenStd(cleanToken.toStdString());
        atom.atomicNumber = Elements::atomicNumberFromName(tokenStd);
        if (atom.atomicNumber == 0)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid element name."));
        else
          m_ui->text->markValid(tokenCursor, tr("Element name."));
        break;
      }

      case 'S': {
        // Validate symbol:
        QString cleanToken(tokenCursor.selectedText().toLower());
        if (!cleanToken.isEmpty())
          cleanToken.replace(0, 1, cleanToken[0].toUpper());
        std::string tokenStd(cleanToken.toStdString());
        atom.atomicNumber = Elements::atomicNumberFromSymbol(tokenStd);
        if (atom.atomicNumber == 0)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid element symbol."));
        else
          m_ui->text->markValid(tokenCursor, tr("Element symbol."));
        break;
      }

      case 'Z': {
        // Validate integer:
        bool isInt;
        atom.atomicNumber = static_cast<unsigned char>(
              tokenCursor.selectedText().toInt(&isInt));
        if (!isInt)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid atomic number."));
        else
          m_ui->text->markValid(tokenCursor, tr("Atomic number."));
        break;
      }

      case 'x': {
        // Validate real:
        bool isReal;
        atom.pos.x() = tokenCursor.selectedText().toDouble(&isReal);
        if (!isReal)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid coordinate."));
        else
          m_ui->text->markValid(tokenCursor, tr("X coordinate."));
        break;
      }

      case 'y': {
        // Validate real:
        bool isReal;
        atom.pos.y() = tokenCursor.selectedText().toDouble(&isReal);
        if (!isReal)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid coordinate."));
        else
          m_ui->text->markValid(tokenCursor, tr("Y coordinate."));
        break;
      }

      case 'z': {
        // Validate real:
        bool isReal;
        atom.pos.z() = tokenCursor.selectedText().toDouble(&isReal);
        if (!isReal)
          m_ui->text->markInvalid(tokenCursor, tr("Invalid coordinate."));
        else
          m_ui->text->markValid(tokenCursor, tr("Z coordinate."));
        break;
      }

      default:
        qWarning() << "Unhandled character in detected spec: " << *iter;
        break;
      }
    }

    // Store this atom info if collecting.
    if (m_validate->collectAtoms) {
      if (m_validate->convertDistance)
        atom.pos *= m_validate->distanceConversion;
      m_validate->atoms << atom;
    }

    // Move to the next line:
    lineCursor.movePosition(QTextCursor::NextCharacter);
  }

  // Reenable validation.
  listenForTextEditChanges(true);

  // If we're not at the end, post this method back into the event loop.
  if (!lineCursor.atEnd()) {
    QTimer::singleShot(0, this, SLOT(validateInputWorker()));
  }
  else {
    // Otherwise emit the finished signal.
    emit validationFinished(!m_ui->text->hasInvalidMarks());
    m_validate->isValidating = false;

    // If a validation request came in while already validating, revalidate.
    if (m_validate->restartWhenFinished) {
      m_validate->restartWhenFinished = false;
      validateInput();
    }
  }
}

void CartesianEditorDialog::applyClicked()
{
  if (!m_molecule)
    return;

  // If we're in the middle of a validation, abort it
  if (m_validate->isValidating) {
    m_validate->isValidating = false;
    qApp->processEvents();
  }

  m_validate->collectAtoms = true;
  m_validate->atoms.clear();

  switch (m_ui->distanceUnit->currentIndex()) {
  case Bohr:
    m_validate->convertDistance = true;
    m_validate->distanceConversion = static_cast<float>(BOHR_TO_ANGSTROM);
    break;
  default:
    m_validate->convertDistance = false;
    m_validate->distanceConversion = 1.f;
    break;
  }

  connect(this, SIGNAL(validationFinished(bool)), SLOT(applyFinish(bool)));
  validateInput();
}

void CartesianEditorDialog::applyFinish(bool valid)
{
  // Clean up
  m_validate->collectAtoms = false;
  QVector<AtomStruct> atoms(m_validate->atoms);
  m_validate->atoms.clear();
  disconnect(this, SIGNAL(validationFinished(bool)),
             this, SLOT(applyFinish(bool)));

  if (!valid) {
    QMessageBox::critical(this, tr("Error applying geometry"),
                          tr("Could not parse geometry specification. Fix the "
                             "highlighted errors and try again.\n\n"
                             "(Hint: Hold the mouse over red text for a "
                             "description of the error.)"));
    return;
  }

  bool hadAtoms(m_molecule->atomCount() > 0);
  bool hadBonds(m_molecule->bondCount() > 0);

  m_molecule->clearAtoms();
  foreach (const AtomStruct &atom, atoms)
    m_molecule->addAtom(atom.atomicNumber).setPosition3d(atom.pos);

  m_ui->text->document()->setModified(false);

  Molecule::MoleculeChanges change = Molecule::NoChange;
  if (hadAtoms)
    change |= Molecule::Atoms | Molecule::Removed;
  if (hadBonds)
    change |= Molecule::Bonds | Molecule::Removed;
  if (!atoms.isEmpty())
    change |= Molecule::Atoms | Molecule::Added;

  if (change != Molecule::NoChange)
    m_molecule->emitChanged(change);
}

void CartesianEditorDialog::buildPresets()
{
  // Custom must be first:
  m_ui->presets->addItem(tr("Custom"), QVariant());
  m_ui->presets->addItem(tr("XYZ format"), QVariant("Sxyz"));
  m_ui->presets->addItem(tr("GAMESS format"), QVariant("SGxyz"));
}

void CartesianEditorDialog::listenForTextEditChanges(bool enable)
{
  if (enable)
    connect(m_ui->text, SIGNAL(textChanged()), this, SLOT(validateInput()));
  else
    disconnect(m_ui->text, SIGNAL(textChanged()), this, SLOT(validateInput()));
}

QString CartesianEditorDialog::detectInputFormat() const
{
  if (m_ui->text->document()->isEmpty())
    return QString();

  // Extract the first non-empty line of text from the document.
  QTextCursor cur(m_ui->text->document());
  QString sample;
  while (sample.isEmpty()) {
    cur.movePosition(QTextCursor::StartOfLine, QTextCursor::MoveAnchor);
    cur.movePosition(QTextCursor::EndOfLine, QTextCursor::KeepAnchor);
    sample = cur.selectedText();
    cur.movePosition(QTextCursor::Down);
  }

  FORMAT_DEBUG(qDebug() << "\n\nExamining sample:" << sample;)

  // Split the string into tokens, and identify the type of each.
  enum TokenType {
    Integer = 0,
    Double,
    String
  };
  QList<QString> tokens(sample.split(TOKEN_SEPARATOR, QString::SkipEmptyParts));
  QList<TokenType> tokenTypes;
  tokenTypes.reserve(tokens.size());
  size_t tokenTypeCounts[3] = {0, 0, 0};

  foreach (const QString &token, tokens) {
    TokenType tokenType = String;
    if (INT_CHECKER.exactMatch(token))
      tokenType = Integer;
    else if (DOUBLE_CHECKER.exactMatch(token))
      tokenType = Double;
    ++tokenTypeCounts[tokenType];
    tokenTypes << tokenType;
  }

  FORMAT_DEBUG(
    qDebug() << "\nDetected types:";
    qDebug() << tokens;
    qDebug() << tokenTypes;
  );

  // If less than three doubles are present, promote some integers to doubles.
  if (tokenTypeCounts[Double] < 3
      && tokenTypeCounts[Double] + tokenTypeCounts[Integer] >= 3) {

    // If numInts + numDoubles is greater than 3, leave the first integer as is,
    // we'll assume it's the atomic number.
    bool skipNextInt(tokenTypeCounts[Integer] + tokenTypeCounts[Double] > 3);

    size_t intsToPromote = 3 - tokenTypeCounts[Double];
    QMutableListIterator<TokenType> tokenTypeIter(tokenTypes);
    while (intsToPromote > 0 && tokenTypeIter.hasNext()) {
      if (tokenTypeIter.next() == Integer) {
        if (!skipNextInt) {
          tokenTypeIter.setValue(Double);
          --intsToPromote;
          --tokenTypeCounts[Integer];
          ++tokenTypeCounts[Double];
        }
        else {
          skipNextInt = false;
        }
      }
    }
  }

  FORMAT_DEBUG(
    qDebug() << "\nAfter promotion:";
    qDebug() << tokens;
    qDebug() << tokenTypes;
  )

  // If there are no strings or integers, bail out -- we can't determine the
  // atom types. Likewise if there are less than 3 doubles, the coordinates
  // are incomplete.
  if ((tokenTypeCounts[Integer] == 0 && tokenTypeCounts[String] == 0)
      || tokenTypeCounts[Double] < 3) {
    return "";
  }

  // Start assigning meaning to the values:
  QString resultSpec;
  bool atomTypeSet(false);
  int numCoordsSet(0);
  const int numberOfElements(static_cast<int>(Core::Elements::elementCount()));

  for (int i = 0; i < tokens.size() && (!atomTypeSet || numCoordsSet < 3);
       ++i) {
    QChar current = '?';

    switch (tokenTypes[i]) {
    case Integer:
      if (!atomTypeSet) {
        int tokenAsInt = tokens[i].toInt();
        if (tokenAsInt > 0 && tokenAsInt <= numberOfElements) {
          current = 'Z';
          atomTypeSet = true;
        }
      }
      break;

    case Double:
      switch (numCoordsSet) {
      case 0:
        current = 'x';
        ++numCoordsSet;
        break;
      case 1:
        current = 'y';
        ++numCoordsSet;
        break;
      case 2:
        current = 'z';
        ++numCoordsSet;
        break;
      default:
        break;
      }
      break;

    case String:
      if (!atomTypeSet) {
        QString cleanToken(tokens[i].toLower());
        if (!cleanToken.isEmpty())
          cleanToken.replace(0, 1, cleanToken[0].toUpper());

        if (cleanToken.size() <= 3) {
          if (Elements::atomicNumberFromSymbol(cleanToken.toStdString()) > 0) {
            current = 'S';
            atomTypeSet = true;
          }
        }
        else {
          if (Elements::atomicNumberFromName(cleanToken.toStdString()) > 0) {
            current = 'N';
            atomTypeSet = true;
          }
        }
      }
      break;

    }

    FORMAT_DEBUG(qDebug() << current << tokens[i];)
    resultSpec += current;
  }

  FORMAT_DEBUG(qDebug() << "Detected format:" << resultSpec);

  return (!atomTypeSet || numCoordsSet < 3) ? QString(): resultSpec;
}

void CartesianEditorDialog::cutClicked()
{
  copyClicked();
  clearClicked();
}

void CartesianEditorDialog::copyClicked()
{
  qApp->clipboard()->setText(m_ui->text->document()->toPlainText());
}

void CartesianEditorDialog::pasteClicked()
{
  const QMimeData *mimeData = qApp->clipboard()->mimeData();
  m_ui->text->document()->setPlainText((mimeData && mimeData->hasText())
                                       ? mimeData->text()
                                       : "");
}

void CartesianEditorDialog::revertClicked()
{
  updateText();
}

void CartesianEditorDialog::clearClicked()
{
  m_ui->text->document()->clear();
}

} // namespace QtPlugins
} // namespace Avogadro

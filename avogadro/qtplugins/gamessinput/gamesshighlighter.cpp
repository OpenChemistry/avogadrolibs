/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright (C) 2009 Marcus D. Hanwell

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "gamesshighlighter.h"

namespace Avogadro {
namespace QtPlugins {

GamessHighlighter::GamessHighlighter(QTextDocument* parent_)
  : QSyntaxHighlighter(parent_)
{
  HighlightingRule rule;

  m_keywordFormat.setForeground(Qt::darkBlue);
  m_keywordFormat.setFontWeight(QFont::Bold);
  m_keywords << "\\s\\$BASIS\\b"
             << "\\s\\$CONTRL\\b"
             << "\\s\\$SYSTEM\\b"
             << "\\s\\$ZMAT\\b"
             << "\\s\\$LIBE\\b"
             << "\\s\\$SCF\\b"
             << "\\s\\$SCFMI\\b"
             << "\\s\\$DFT\\b"
             << "\\s\\$TDDFT\\b"
             << "\\s\\$CIS\\b"
             << "\\s\\$CISVEC\\b"
             << "\\s\\$MP2\\b"
             << "\\s\\$CCINP\\b"
             << "\\s\\$EOMINP\\b"
             << "\\s\\$MOPAC\\b"
             << "\\s\\$GUESS\\b"
             << "\\s\\$VEC\\b"
             << "\\s\\$MOFRZ\\b"
             << "\\s\\$STATPT\\b"
             << "\\s\\$TRUDGE\\b"
             << "\\s\\$TRURST\\b"
             << "\\s\\$FORCE\\b"
             << "\\s\\$CPHF\\b"
             << "\\s\\$MASS\\b"
             << "\\s\\$HESS\\b"
             << "\\s\\$GRAD\\b"
             << "\\s\\$DIPDR\\b"
             << "\\s\\$VIB\\b"
             << "\\s\\$VIB2\\b"
             << "\\s\\$VSCF\\b"
             << "\\s\\$VIBSCF\\b"
             << "\\s\\$GAMMA\\b"
             << "\\s\\$EQGEOM\\b"
             << "\\s\\$HLOWT\\b"
             << "\\s\\$GLOWT\\b"
             << "\\s\\$IRC\\b"
             << "\\s\\$DRC\\b"
             << "\\s\\$MEX\\b"
             << "\\s\\$MD\\b"
             << "\\s\\$RDF\\b"
             << "\\s\\$GLOBOP\\b"
             << "\\s\\$GRADEX\\b"
             << "\\s\\$SURF\\b"
             << "\\s\\$LOCAL\\b"
             << "\\s\\$TWOEI\\b"
             << "\\s\\$TRUNCN\\b"
             << "\\s\\$ELMOM\\b"
             << "\\s\\$ELPOT\\b"
             << "\\s\\$ELDENS\\b"
             << "\\s\\$ELFLDG\\b"
             << "\\s\\$POINTS\\b"
             << "\\s\\$GRID\\b"
             << "\\s\\$PDC\\b"
             << "\\s\\$MOLGRF\\b"
             << "\\s\\$STONE\\b"
             << "\\s\\$RAMAN\\b"
             << "\\s\\$ALPDR\\b"
             << "\\s\\$NMR\\b"
             << "\\s\\$MOROKM\\b"
             << "\\s\\$FFCALC\\b"
             << "\\s\\$TDHF\\b"
             << "\\s\\$TDHFX\\b"
             << "\\s\\$EFRAG\\b"
             << "\\s\\$FRAGNAME\\b"
             << "\\s\\$FRGRPL\\b"
             << "\\s\\$EWALD\\b"
             << "\\s\\$MAKEFP\\b"
             << "\\s\\$PRTEFP\\b"
             << "\\s\\$DAMP\\b"
             << "\\s\\$DAMPGS\\b"
             << "\\s\\$PCM\\b"
             << "\\s\\$PCMGRD\\b"
             << "\\s\\$PCMCAV\\b"
             << "\\s\\$TESCAV\\b"
             << "\\s\\$NEWCAV\\b"
             << "\\s\\$IEFPCM\\b"
             << "\\s\\$PCMITR\\b"
             << "\\s\\$DISBS\\b"
             << "\\s\\$DISREP\\b"
             << "\\s\\$SVP\\b"
             << "\\s\\$SVPIRF\\b"
             << "\\s\\$COSGMS\\b"
             << "\\s\\$SCRF\\b"
             << "\\s\\$ECP\\b"
             << "\\s\\$MCP\\b"
             << "\\s\\$RELWFN\\b"
             << "\\s\\$EFIELD\\b"
             << "\\s\\$INTGRL\\b"
             << "\\s\\$FMM\\b"
             << "\\s\\$TRANS\\b"
             << "\\s\\$FMO\\b"
             << "\\s\\$FMOPRP\\b"
             << "\\s\\$FMOXYZ\\b"
             << "\\s\\$OPTFMO\\b"
             << "\\s\\$FMOHYB\\b"
             << "\\s\\$FMOBND\\b"
             << "\\s\\$FMOENM\\b"
             << "\\s\\$FMOEND\\b"
             << "\\s\\$OPTRST\\b"
             << "\\s\\$GDDI\\b"
             << "\\s\\$ELG\\b"
             << "\\s\\$DANDC\\b"
             << "\\s\\$DCCORR\\b"
             << "\\s\\$SUBSCF\\b"
             << "\\s\\$SUBCOR\\b"
             << "\\s\\$MP2RES\\b"
             << "\\s\\$CCRES\\b"
             << "\\s\\$CIINP\\b"
             << "\\s\\$DET\\b"
             << "\\s\\$CIDET\\b"
             << "\\s\\$GEN\\b"
             << "\\s\\$CIGEN\\b"
             << "\\s\\$ORMAS\\b"
             << "\\s\\$CEEIS\\b"
             << "\\s\\$CEDATA\\b"
             << "\\s\\$GCILST\\b"
             << "\\s\\$GMCPT\\b"
             << "\\s\\$PDET\\b"
             << "\\s\\$ADDDET\\b"
             << "\\s\\$REMDET\\b"
             << "\\s\\$SODET\\b"
             << "\\s\\$DRT\\b"
             << "\\s\\$CIDRT\\b"
             << "\\s\\$MCSCF\\b"
             << "\\s\\$MRMP\\b"
             << "\\s\\$DETPT\\b"
             << "\\s\\$MCQDPT\\b"
             << "\\s\\$CASCI\\b"
             << "\\s\\$IVOORB\\b"
             << "\\s\\$CISORT\\b"
             << "\\s\\$GUGEM\\b"
             << "\\s\\$GUGDIA\\b"
             << "\\s\\$GUGDM\\b"
             << "\\s\\$GUGDM2\\b"
             << "\\s\\$LAGRAN\\b"
             << "\\s\\$TRFDM2\\b"
             << "\\s\\$TRANST\\b"
             << "\\s\\$DATA\\b";
  rule.format = m_keywordFormat;
  foreach (const QString& pattern, m_keywords) {
    rule.pattern = QRegExp(pattern);
    m_highlightingRules.append(rule);
  }
  rule.pattern = QRegExp("\\s\\$END\\b");
  m_highlightingRules.append(rule);

  m_singleLineCommentFormat.setForeground(Qt::green);
  rule.pattern = QRegExp("![^\n]*");
  rule.format = m_singleLineCommentFormat;
  m_highlightingRules.append(rule);

  m_numberFormat.setForeground(Qt::blue);
  rule.pattern = QRegExp("(\\b|[\\s-])[0-9]+\\.([0-9]+\\b)?|\\.[0-9]+\\b");
  rule.format = m_numberFormat;
  m_highlightingRules.append(rule);

  m_numberFormat.setForeground(Qt::blue);
  rule.pattern = QRegExp("(\\b|[\\s-])[0-9]+\\.([0-9]+\\b)?|\\.[0-9]+\\b");
  rule.format = m_numberFormat;
  m_highlightingRules.append(rule);
  rule.pattern = QRegExp("(\\b|[\\s-])[0-9]+([0-9]+\\b)?|\\.[0-9]+\\b");
  rule.format = m_numberFormat;
  m_highlightingRules.append(rule);

  m_inDataBlockFormat.setForeground(Qt::gray);

  m_errorFormat.setForeground(Qt::red);
  m_errorFormat.setBackground(Qt::yellow);
}

void GamessHighlighter::highlightBlock(const QString& text)
{
  // Single line comments
  QRegExp pattern("![^\n]*");
  int commentIndex = pattern.indexIn(text);
  if (commentIndex >= 0)
    setFormat(commentIndex, pattern.matchedLength(), m_singleLineCommentFormat);

  setCurrentBlockState(0);

  int startIndex = 0;
  int keywordLength = 0;
  if (previousBlockState() != 1) {
    foreach (const QString& regexString, m_keywords) {
      QRegExp expression(regexString);
      expression.setCaseSensitivity(Qt::CaseInsensitive);
      startIndex = expression.indexIn(text);
      keywordLength = expression.matchedLength();
      if (startIndex >= 0) {
        setFormat(startIndex, keywordLength, m_keywordFormat);
        break;
      }
    }
  }

  while (startIndex >= 0) {
    QRegExp endExpression("\\s\\$END\\b");
    endExpression.setCaseSensitivity(Qt::CaseInsensitive);
    int endIndex = endExpression.indexIn(text, startIndex);
    int blockLength;
    if (endIndex == -1) {
      setCurrentBlockState(1);
      blockLength = text.length() - startIndex - keywordLength;
    } else {
      setFormat(endIndex, endExpression.matchedLength(), m_keywordFormat);
      blockLength = endIndex - startIndex - keywordLength;
    }
    setFormat(startIndex + keywordLength, blockLength, m_inDataBlockFormat);
    bool found = false;
    foreach (const QString& regexString, m_keywords) {
      QRegExp expression(regexString);
      int index = expression.indexIn(text, startIndex + blockLength);
      if (index > startIndex) {
        found = true;
        startIndex = index;
        keywordLength = expression.matchedLength();
        setFormat(startIndex, keywordLength, m_keywordFormat);
        break;
      }
    }
    if (!found)
      break;
  }

  if (previousBlockState() ==
      1) { // Anything outside of data blocks is a comment
    foreach (const HighlightingRule& rule, m_highlightingRules) {
      QRegExp expression(rule.pattern);
      expression.setCaseSensitivity(Qt::CaseInsensitive);
      int index = text.indexOf(expression);
      while (index >= 0) {
        int length = expression.matchedLength();
        setFormat(index, length, rule.format);
        index = text.indexOf(expression, index + length);
      }
    }
  }

  // Anything over 80 columns will not be read
  if (text.length() > 80)
    setFormat(80, text.length(), m_errorFormat);
}

} // End namespace QtPlugins
} // End namespace Avogadro

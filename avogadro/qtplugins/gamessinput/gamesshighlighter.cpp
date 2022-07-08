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

namespace Avogadro::QtPlugins {

GamessHighlighter::GamessHighlighter(QTextDocument* parent_)
  : QSyntaxHighlighter(parent_)
{
  HighlightingRule rule;

  m_keywordFormat.setForeground(Qt::darkBlue);
  m_keywordFormat.setFontWeight(QFont::Bold);
  m_keywords << R"(\s\$BASIS\b)"
             << R"(\s\$CONTRL\b)"
             << R"(\s\$SYSTEM\b)"
             << R"(\s\$ZMAT\b)"
             << R"(\s\$LIBE\b)"
             << R"(\s\$SCF\b)"
             << R"(\s\$SCFMI\b)"
             << R"(\s\$DFT\b)"
             << R"(\s\$TDDFT\b)"
             << R"(\s\$CIS\b)"
             << R"(\s\$CISVEC\b)"
             << R"(\s\$MP2\b)"
             << R"(\s\$CCINP\b)"
             << R"(\s\$EOMINP\b)"
             << R"(\s\$MOPAC\b)"
             << R"(\s\$GUESS\b)"
             << R"(\s\$VEC\b)"
             << R"(\s\$MOFRZ\b)"
             << R"(\s\$STATPT\b)"
             << R"(\s\$TRUDGE\b)"
             << R"(\s\$TRURST\b)"
             << R"(\s\$FORCE\b)"
             << R"(\s\$CPHF\b)"
             << R"(\s\$MASS\b)"
             << R"(\s\$HESS\b)"
             << R"(\s\$GRAD\b)"
             << R"(\s\$DIPDR\b)"
             << R"(\s\$VIB\b)"
             << R"(\s\$VIB2\b)"
             << R"(\s\$VSCF\b)"
             << R"(\s\$VIBSCF\b)"
             << R"(\s\$GAMMA\b)"
             << R"(\s\$EQGEOM\b)"
             << R"(\s\$HLOWT\b)"
             << R"(\s\$GLOWT\b)"
             << R"(\s\$IRC\b)"
             << R"(\s\$DRC\b)"
             << R"(\s\$MEX\b)"
             << R"(\s\$MD\b)"
             << R"(\s\$RDF\b)"
             << R"(\s\$GLOBOP\b)"
             << R"(\s\$GRADEX\b)"
             << R"(\s\$SURF\b)"
             << R"(\s\$LOCAL\b)"
             << R"(\s\$TWOEI\b)"
             << R"(\s\$TRUNCN\b)"
             << R"(\s\$ELMOM\b)"
             << R"(\s\$ELPOT\b)"
             << R"(\s\$ELDENS\b)"
             << R"(\s\$ELFLDG\b)"
             << R"(\s\$POINTS\b)"
             << R"(\s\$GRID\b)"
             << R"(\s\$PDC\b)"
             << R"(\s\$MOLGRF\b)"
             << R"(\s\$STONE\b)"
             << R"(\s\$RAMAN\b)"
             << R"(\s\$ALPDR\b)"
             << R"(\s\$NMR\b)"
             << R"(\s\$MOROKM\b)"
             << R"(\s\$FFCALC\b)"
             << R"(\s\$TDHF\b)"
             << R"(\s\$TDHFX\b)"
             << R"(\s\$EFRAG\b)"
             << R"(\s\$FRAGNAME\b)"
             << R"(\s\$FRGRPL\b)"
             << R"(\s\$EWALD\b)"
             << R"(\s\$MAKEFP\b)"
             << R"(\s\$PRTEFP\b)"
             << R"(\s\$DAMP\b)"
             << R"(\s\$DAMPGS\b)"
             << R"(\s\$PCM\b)"
             << R"(\s\$PCMGRD\b)"
             << R"(\s\$PCMCAV\b)"
             << R"(\s\$TESCAV\b)"
             << R"(\s\$NEWCAV\b)"
             << R"(\s\$IEFPCM\b)"
             << R"(\s\$PCMITR\b)"
             << R"(\s\$DISBS\b)"
             << R"(\s\$DISREP\b)"
             << R"(\s\$SVP\b)"
             << R"(\s\$SVPIRF\b)"
             << R"(\s\$COSGMS\b)"
             << R"(\s\$SCRF\b)"
             << R"(\s\$ECP\b)"
             << R"(\s\$MCP\b)"
             << R"(\s\$RELWFN\b)"
             << R"(\s\$EFIELD\b)"
             << R"(\s\$INTGRL\b)"
             << R"(\s\$FMM\b)"
             << R"(\s\$TRANS\b)"
             << R"(\s\$FMO\b)"
             << R"(\s\$FMOPRP\b)"
             << R"(\s\$FMOXYZ\b)"
             << R"(\s\$OPTFMO\b)"
             << R"(\s\$FMOHYB\b)"
             << R"(\s\$FMOBND\b)"
             << R"(\s\$FMOENM\b)"
             << R"(\s\$FMOEND\b)"
             << R"(\s\$OPTRST\b)"
             << R"(\s\$GDDI\b)"
             << R"(\s\$ELG\b)"
             << R"(\s\$DANDC\b)"
             << R"(\s\$DCCORR\b)"
             << R"(\s\$SUBSCF\b)"
             << R"(\s\$SUBCOR\b)"
             << R"(\s\$MP2RES\b)"
             << R"(\s\$CCRES\b)"
             << R"(\s\$CIINP\b)"
             << R"(\s\$DET\b)"
             << R"(\s\$CIDET\b)"
             << R"(\s\$GEN\b)"
             << R"(\s\$CIGEN\b)"
             << R"(\s\$ORMAS\b)"
             << R"(\s\$CEEIS\b)"
             << R"(\s\$CEDATA\b)"
             << R"(\s\$GCILST\b)"
             << R"(\s\$GMCPT\b)"
             << R"(\s\$PDET\b)"
             << R"(\s\$ADDDET\b)"
             << R"(\s\$REMDET\b)"
             << R"(\s\$SODET\b)"
             << R"(\s\$DRT\b)"
             << R"(\s\$CIDRT\b)"
             << R"(\s\$MCSCF\b)"
             << R"(\s\$MRMP\b)"
             << R"(\s\$DETPT\b)"
             << R"(\s\$MCQDPT\b)"
             << R"(\s\$CASCI\b)"
             << R"(\s\$IVOORB\b)"
             << R"(\s\$CISORT\b)"
             << R"(\s\$GUGEM\b)"
             << R"(\s\$GUGDIA\b)"
             << R"(\s\$GUGDM\b)"
             << R"(\s\$GUGDM2\b)"
             << R"(\s\$LAGRAN\b)"
             << R"(\s\$TRFDM2\b)"
             << R"(\s\$TRANST\b)"
             << R"(\s\$DATA\b)";
  rule.format = m_keywordFormat;
  foreach (const QString& pattern, m_keywords) {
    rule.pattern = QRegExp(pattern);
    m_highlightingRules.append(rule);
  }
  rule.pattern = QRegExp(R"(\s\$END\b)");
  m_highlightingRules.append(rule);

  m_singleLineCommentFormat.setForeground(Qt::green);
  rule.pattern = QRegExp("![^\n]*");
  rule.format = m_singleLineCommentFormat;
  m_highlightingRules.append(rule);

  m_numberFormat.setForeground(Qt::blue);
  rule.pattern = QRegExp(R"((\b|[\s-])[0-9]+\.([0-9]+\b)?|\.[0-9]+\b)");
  rule.format = m_numberFormat;
  m_highlightingRules.append(rule);

  m_numberFormat.setForeground(Qt::blue);
  rule.pattern = QRegExp(R"((\b|[\s-])[0-9]+\.([0-9]+\b)?|\.[0-9]+\b)");
  rule.format = m_numberFormat;
  m_highlightingRules.append(rule);
  rule.pattern = QRegExp(R"((\b|[\s-])[0-9]+([0-9]+\b)?|\.[0-9]+\b)");
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
    QRegExp endExpression(R"(\s\$END\b)");
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

} // End namespace Avogadro

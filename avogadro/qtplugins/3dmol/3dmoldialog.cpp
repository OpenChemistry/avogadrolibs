#include "3dmoldialog.h"
#include "ui_3dmoldialog.h"

#include <avogadro/core/elements.h>
#include <avogadro/qtgui/molecule.h>

#include <QtDebug>

using Avogadro::QtGui::Molecule;

namespace Avogadro {
namespace QtPlugins {

ThreeDMolDialog::ThreeDMolDialog(QtGui::Molecule *mol, QWidget *parent_)
  : QDialog(parent_),
    m_molecule(NULL),
    m_ui(new Ui::ThreeDMolDialog)
{
  m_ui->setupUi(this);
  setMolecule(mol);
}

ThreeDMolDialog::~ThreeDMolDialog()
{
  delete m_ui;
}

void ThreeDMolDialog::setMolecule(QtGui::Molecule *mol)
{
  if (mol == m_molecule)
    return;

  if (m_molecule)
    m_molecule->disconnect(this);

  m_molecule = mol;

  if (!m_molecule)
    return;

  connect(m_molecule, SIGNAL(changed(unsigned int)), SLOT(updateLabels()));
  connect(m_molecule, SIGNAL(destroyed()), SLOT(moleculeDestroyed()));
  updateLabels();
}

void ThreeDMolDialog::updateLabels()
{
  if (m_molecule) {
    updateTextBrowser();
  }
  else {
    m_ui->textBrowser->clear();
  }
}

void ThreeDMolDialog::updateTextBrowser()
{
  QString text = "<script src='http://3Dmol.csb.pitt.edu/build/3Dmol-min.js'></script>\n";
  text.append("<div style='height: 400px; width: 400px; position: relative;' class='viewer_3Dmoljs' data-element='moleculeXYZ' data-type='xyz' data-backgroundcolor='0xffffff' data-style='stick'></div>\n");
  text.append("<textarea id='moleculeXYZ' style='display: none;'>");
  // Now put in the XYZ coords
  text.append("<textarea>");
  m_ui->textBrowser->setText(text.toHtmlEscaped());
}

void ThreeDMolDialog::moleculeDestroyed()
{
  m_molecule = NULL;
  updateLabels();
}

} // namespace QtPlugins
} // namespace Avogadro

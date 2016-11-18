/******************************************************************************

  This source file is part of the Avogadro project.

  Copyright 2014 Kitware, Inc.

  This source code is released under the New BSD License, (the "License").

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

******************************************************************************/

#include "playertool.h"

#include <avogadro/core/vector.h>
#include <avogadro/qtgui/molecule.h>

#include <QtCore/QProcess>
#include <QtGui/QIcon>
#include <QtWidgets/QAction>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QFileDialog>
#include <QtOpenGL/QGLWidget>
#include <QtOpenGL/QGLFramebufferObject>

#include <QDebug>

#include <cmath>

namespace Avogadro {
namespace QtPlugins {

using QtGui::Molecule;

PlayerTool::PlayerTool(QObject *parent_)
  : QtGui::ToolPlugin(parent_),
    m_activateAction(new QAction(this)),
    m_molecule(NULL),
    m_renderer(NULL),
    m_currentFrame(0),
    m_toolWidget(NULL),
    m_info(NULL)
{
  m_activateAction->setText(tr("Player"));
  m_activateAction->setIcon(QIcon(":/icons/player.png"));
}

PlayerTool::~PlayerTool()
{
}

QWidget * PlayerTool::toolWidget() const
{
  if (!m_toolWidget) {
    m_toolWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout *layout = new QVBoxLayout;
    QHBoxLayout *controls = new QHBoxLayout;
    controls->addStretch(1);
    QPushButton *button = new QPushButton("<");
    connect(button, SIGNAL(clicked()), SLOT(back()));
    controls->addWidget(button);
    button = new QPushButton(tr("Play"));
    connect(button, SIGNAL(clicked()), SLOT(play()));
    controls->addWidget(button);
    button = new QPushButton(tr("Stop"));
    connect(button, SIGNAL(clicked()), SLOT(stop()));
    controls->addWidget(button);
    button = new QPushButton(">");
    connect(button, SIGNAL(clicked()), SLOT(forward()));
    controls->addWidget(button);
    controls->addStretch(1);
    layout->addLayout(controls);

    QHBoxLayout *frames = new QHBoxLayout;
    QLabel *label = new QLabel(tr("Frame rate:"));
    frames->addWidget(label);
    m_animationFPS = new QSpinBox;
    m_animationFPS->setValue(5);
    m_animationFPS->setMinimum(0);
    m_animationFPS->setMaximum(100);
    m_animationFPS->setSuffix(tr(" FPS", "frames per second"));
    frames->addWidget(m_animationFPS);
    layout->addLayout(frames);

    QHBoxLayout *bonding = new QHBoxLayout;
    bonding->addStretch(1);
    m_dynamicBonding = new QCheckBox(tr("Dynamic bonding?"));
    m_dynamicBonding->setChecked(true);
    bonding->addWidget(m_dynamicBonding);
    bonding->addStretch(1);
    layout->addLayout(bonding);

    QHBoxLayout *recordLayout = new QHBoxLayout;
    recordLayout->addStretch(1);
    button = new QPushButton(tr("Record Movie..."));
    connect(button, SIGNAL(clicked()), SLOT(recordMovie()));
    recordLayout->addWidget(button);
    recordLayout->addStretch(1);
    layout->addLayout(recordLayout);

    m_info = new QLabel(tr("Stopped"));
    layout->addWidget(m_info);
    m_toolWidget->setLayout(layout);
  }
  connect(&m_timer, SIGNAL(timeout()), SLOT(animate()));

  return m_toolWidget;
}

QUndoCommand * PlayerTool::mousePressEvent(QMouseEvent *)
{
  return NULL;
}

QUndoCommand * PlayerTool::mouseReleaseEvent(QMouseEvent *)
{
  return NULL;
}

QUndoCommand *PlayerTool::mouseDoubleClickEvent(QMouseEvent *)
{
  return NULL;
}

void PlayerTool::setActiveWidget(QWidget *widget)
{
  m_glWidget = qobject_cast<QGLWidget *>(widget);
}

void PlayerTool::back()
{
  animate(-1);
}

void PlayerTool::forward()
{
  animate(1);
}

void PlayerTool::play()
{
  double fps = static_cast<double>(m_animationFPS->value());
  if (fps < 0.00001)
    fps = 5;
  int timeOut = static_cast<int>(1000 / fps);
  if (m_timer.isActive())
    m_timer.stop();
  m_timer.start(timeOut);
}

void PlayerTool::stop()
{
  m_timer.stop();
  m_info->setText(tr("Stopped"));
}

void PlayerTool::animate(int advance)
{
  if (m_molecule) {
    if (m_currentFrame < m_molecule->coordinate3dCount() - advance
        && m_currentFrame + advance >= 0) {
      m_currentFrame += advance;
      m_molecule->setCoordinate3d(m_currentFrame);
    }
    else {
      m_currentFrame = advance > 0 ? 0 : m_molecule->coordinate3dCount() - 1;
      m_molecule->setCoordinate3d(m_currentFrame);
    }
    if (m_dynamicBonding->isChecked()) {
      m_molecule->clearBonds();
      m_molecule->perceiveBondsSimple();
    }
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Added);
    m_info->setText(tr("Frame %0 of %1").arg(m_currentFrame + 1)
                    .arg(m_molecule->coordinate3dCount()));
  }
}

void PlayerTool::recordMovie()
{
  if (m_timer.isActive())
    m_timer.stop();

  QString baseFileName;
  if (m_molecule)
    baseFileName = m_molecule->data("fileName").toString().c_str();
  QFileInfo info(baseFileName);

  QString baseName = QFileDialog::getSaveFileName(qobject_cast<QWidget*>(parent()),
                                                  tr("Export Bitmap Graphics"),
                                                  "",
                                                  "Movie (*.mp4)");

  if (baseName.isEmpty())
    return;
  if (!QFileInfo(baseName).suffix().isEmpty())
    baseName = QFileInfo(baseName).baseName();

  bool bonding = m_dynamicBonding->isChecked();
  int numberLength =
      static_cast<int>(ceil(log10(static_cast<float>(m_molecule->coordinate3dCount()) + 1)));
  m_glWidget->resize(800, 600);
  for (int i = 0; i < m_molecule->coordinate3dCount(); ++i) {
    m_molecule->setCoordinate3d(i);
    if (bonding) {
      m_molecule->clearBonds();
      m_molecule->perceiveBondsSimple();
    }
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Modified);
    QString fileName = QString::number(i);
    while (fileName.length() < numberLength)
      fileName.prepend('0');
    fileName.prepend(baseName);
    fileName.append(".png");

    QImage exportImage;
    m_glWidget->raise();
    m_glWidget->repaint();
    if (QGLFramebufferObject::hasOpenGLFramebufferObjects()) {
      exportImage = m_glWidget->grabFrameBuffer(true);
    }
    else {
      QPixmap pixmap = QPixmap::grabWindow(m_glWidget->winId());
      exportImage = pixmap.toImage();
    }

    if (!exportImage.save(fileName)) {
      QMessageBox::warning(qobject_cast<QWidget *>(parent()), tr("Avogadro"),
                           tr("Cannot save file %1.").arg(fileName));
      return;
    }
  }
  QProcess proc;
  QStringList args;
  args << "-y" << "-r" << QString::number(m_animationFPS->value())
       << "-i" << baseName + "%0" + QString::number(numberLength) + "d.png"
       << "-c:v" << "libx264" << "-r" << "30" << "-pix_fmt" << "yuv420p"
       << baseName + ".mp4";
  proc.execute("avconv", args);

  args.clear();
  args << "-dispose" << "Background" << "-delay" << QString::number(100 / m_animationFPS->value())
       << baseName + "%0" + QString::number(numberLength) + "d.png[0-" + QString::number(m_molecule->coordinate3dCount() - 1) + "]"
       << baseName + ".gif";
  proc.execute("convert", args);
}

} // namespace QtPlugins
} // namespace Avogadro

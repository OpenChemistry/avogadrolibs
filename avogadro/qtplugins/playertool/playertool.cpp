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
#include <QtGui/QOpenGLFramebufferObject>
#include <QtWidgets/QAction>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QOpenGLWidget>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSlider>
#include <QtWidgets/QSpinBox>
#include <QtWidgets/QVBoxLayout>

#include <QDebug>

#include <cmath>

namespace Avogadro {
namespace QtPlugins {

using QtGui::Molecule;

PlayerTool::PlayerTool(QObject* parent_)
  : QtGui::ToolPlugin(parent_)
  , m_activateAction(new QAction(this))
  , m_molecule(nullptr)
  , m_renderer(nullptr)
  , m_currentFrame(0)
  , m_toolWidget(nullptr)
  , m_frameIdx(nullptr)
  , m_slider(nullptr)
{
  m_activateAction->setText(tr("Player"));
  m_activateAction->setIcon(QIcon(":/icons/player.png"));
}

PlayerTool::~PlayerTool() {}

QWidget* PlayerTool::toolWidget() const
{
  if (!m_toolWidget) {
    m_toolWidget = new QWidget(qobject_cast<QWidget*>(parent()));
    QVBoxLayout* layout = new QVBoxLayout;
    QHBoxLayout* controls = new QHBoxLayout;
    controls->addStretch(1);
    QPushButton* leftButton = new QPushButton("<");
    connect(leftButton, SIGNAL(clicked()), SLOT(back()));
    controls->addWidget(leftButton);
    playButton = new QPushButton(tr("Play"));
    connect(playButton, SIGNAL(clicked()), SLOT(play()));
    controls->addWidget(playButton);
    stopButton = new QPushButton(tr("Stop"));
    connect(stopButton, SIGNAL(clicked()), SLOT(stop()));
    controls->addWidget(stopButton);
    stopButton->setEnabled(false);
    QPushButton* rightButton = new QPushButton(">");
    connect(rightButton, SIGNAL(clicked()), SLOT(forward()));
    controls->addWidget(rightButton);
    controls->addStretch(1);
    layout->addLayout(controls);

    QHBoxLayout* frames = new QHBoxLayout;
    QLabel* label = new QLabel(tr("Frame rate:"));
    frames->addWidget(label);
    m_animationFPS = new QSpinBox;
    m_animationFPS->setValue(5);
    m_animationFPS->setMinimum(0);
    m_animationFPS->setMaximum(100);
    m_animationFPS->setSuffix(tr(" FPS", "frames per second"));
    frames->addWidget(m_animationFPS);
    layout->addLayout(frames);

    QHBoxLayout* sliderLayout = new QHBoxLayout;
    m_slider = new QSlider(Qt::Horizontal);
    m_slider->setMinimum(0);
    m_slider->setTickInterval(1);
    connect(m_slider, SIGNAL(valueChanged(int)),
            SLOT(sliderPositionChanged(int)));
    sliderLayout->addWidget(m_slider);
    layout->addLayout(sliderLayout);
    if (m_molecule->coordinate3dCount() > 1)
      m_slider->setMaximum(m_molecule->coordinate3dCount() - 1);

    QHBoxLayout* frameLayout = new QHBoxLayout;

    // QHBoxLayout* leftColumn = new QHBoxLayout;
    // QLabel* label2 = new QLabel(tr("Timestep:"));
    // leftColumn->addWidget(label2);
    // frameLayout->addLayout(leftColumn);

    QHBoxLayout* rightColumn = new QHBoxLayout;
    rightColumn->addStretch(1);
    QLabel* label3 = new QLabel(tr("Frame:"));
    rightColumn->addWidget(label3);
    m_frameIdx = new QSpinBox;
    m_frameIdx->setValue(1);
    m_frameIdx->setMinimum(1);
    if (m_molecule->coordinate3dCount() > 1) {
      m_frameIdx->setMaximum(m_molecule->coordinate3dCount());
      m_frameIdx->setSuffix(tr(" of %0").arg(m_molecule->coordinate3dCount()));
    }
    connect(m_frameIdx, SIGNAL(valueChanged(int)),
            SLOT(spinnerPositionChanged(int)));
    rightColumn->addWidget(m_frameIdx);
    frameLayout->addLayout(rightColumn);

    layout->addLayout(frameLayout);

    QHBoxLayout* bonding = new QHBoxLayout;
    bonding->addStretch(1);
    m_dynamicBonding = new QCheckBox(tr("Dynamic bonding?"));
    m_dynamicBonding->setChecked(true);
    bonding->addWidget(m_dynamicBonding);
    bonding->addStretch(1);
    layout->addLayout(bonding);

    QHBoxLayout* recordLayout = new QHBoxLayout;
    recordLayout->addStretch(1);
    QPushButton* recordButton = new QPushButton(tr("Record Movie..."));
    connect(recordButton, SIGNAL(clicked()), SLOT(recordMovie()));
    recordLayout->addWidget(recordButton);
    recordLayout->addStretch(1);
    layout->addLayout(recordLayout);

    m_toolWidget->setLayout(layout);
  }
  connect(&m_timer, SIGNAL(timeout()), SLOT(animate()));

  return m_toolWidget;
}

QUndoCommand* PlayerTool::mousePressEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* PlayerTool::mouseReleaseEvent(QMouseEvent*)
{
  return nullptr;
}

QUndoCommand* PlayerTool::mouseDoubleClickEvent(QMouseEvent*)
{
  return nullptr;
}

void PlayerTool::setActiveWidget(QWidget* widget)
{
  m_glWidget = qobject_cast<QOpenGLWidget*>(widget);
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
  playButton->setEnabled(false);
  stopButton->setEnabled(true);
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
  playButton->setEnabled(true);
  stopButton->setEnabled(false);
  m_timer.stop();
}

void PlayerTool::animate(int advance)
{
  if (m_molecule) {
    if (m_currentFrame < m_molecule->coordinate3dCount() - advance &&
        m_currentFrame + advance >= 0) {
      m_currentFrame += advance;
      m_molecule->setCoordinate3d(m_currentFrame);
    } else {
      m_currentFrame = advance > 0 ? 0 : m_molecule->coordinate3dCount() - 1;
      m_molecule->setCoordinate3d(m_currentFrame);
    }
    if (m_dynamicBonding->isChecked()) {
      m_molecule->clearBonds();
      m_molecule->perceiveBondsSimple();
    }
    m_molecule->emitChanged(Molecule::Atoms | Molecule::Added);
    m_slider->setValue(m_currentFrame);
    m_frameIdx->setValue(m_currentFrame + 1);
  }
}

void PlayerTool::recordMovie()
{
  if (m_timer.isActive())
    m_timer.stop();

  QString baseFileName;
  if (m_molecule)
    baseFileName = m_molecule->data("fileName").toString().c_str();

  QString baseName = QFileDialog::getSaveFileName(
    qobject_cast<QWidget*>(parent()), tr("Export Bitmap Graphics"), "",
    "Movie (*.mp4)");

  if (baseName.isEmpty())
    return;

  QFileInfo fileInfo(baseName);
  if (!fileInfo.suffix().isEmpty())
    baseName = fileInfo.canonicalPath() + "/" + fileInfo.baseName();

  bool bonding = m_dynamicBonding->isChecked();
  int numberLength = static_cast<int>(
    ceil(log10(static_cast<float>(m_molecule->coordinate3dCount()) + 1)));
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
    if (QOpenGLFramebufferObject::hasOpenGLFramebufferObjects()) {
      exportImage = m_glWidget->grabFramebuffer();
    } else {
      QPixmap pixmap = QPixmap::grabWindow(m_glWidget->winId());
      exportImage = pixmap.toImage();
    }

    if (!exportImage.save(fileName)) {
      QMessageBox::warning(qobject_cast<QWidget*>(parent()), tr("Avogadro"),
                           tr("Cannot save file %1.").arg(fileName));
      return;
    }
  }
  QProcess proc;
  QStringList args;
  args << "-y"
       << "-r" << QString::number(m_animationFPS->value()) << "-i"
       << baseName + "%0" + QString::number(numberLength) + "d.png"
       << "-c:v"
       << "libx264"
       << "-r"
       << "30"
       << "-pix_fmt"
       << "yuv420p" << baseName + ".mp4";
  proc.execute("avconv", args);

  args.clear();
  args << "-dispose"
       << "Background"
       << "-delay" << QString::number(100 / m_animationFPS->value())
       << baseName + "%0" + QString::number(numberLength) + "d.png[0-" +
            QString::number(m_molecule->coordinate3dCount() - 1) + "]"
       << baseName + ".gif";
  proc.execute("convert", args);
}

void PlayerTool::sliderPositionChanged(int k)
{
  animate(k - m_currentFrame);
}

void PlayerTool::spinnerPositionChanged(int k)
{
  animate(k - m_currentFrame - 1);
}

void PlayerTool::setSliderLimit()
{
  if (m_molecule->coordinate3dCount() > 1 && m_slider)
    m_slider->setMaximum(m_molecule->coordinate3dCount() - 1);
  if (m_molecule->coordinate3dCount() > 1 && m_frameIdx) {
    m_frameIdx->setMaximum(m_molecule->coordinate3dCount());
    m_frameIdx->setSuffix(tr(" of %0").arg(m_molecule->coordinate3dCount()));
  }
}

} // namespace QtPlugins
} // namespace Avogadro

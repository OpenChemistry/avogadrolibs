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

#include <QtWidgets/QAction>
#include <QtGui/QIcon>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QCheckBox>

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
  //m_activateAction->setIcon(QIcon(":/icons/PlayerTool.png"));
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
    m_animationFPS = new QLineEdit;
    frames->addWidget(m_animationFPS);
    layout->addLayout(frames);

    QHBoxLayout *bonding = new QHBoxLayout;
    bonding->addStretch(1);
    m_dynamicBonding = new QCheckBox("Dynamic bonding?");
    m_dynamicBonding->setChecked(true);
    bonding->addWidget(m_dynamicBonding);
    bonding->addStretch(1);
    layout->addLayout(bonding);

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
  bool ok;
  double fps = m_animationFPS->text().toDouble(&ok);
  if (!ok || fps < 0.00001)
    fps = 5;
  int timeOut = static_cast<int>(1000 / fps);
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

} // namespace QtPlugins
} // namespace Avogadro

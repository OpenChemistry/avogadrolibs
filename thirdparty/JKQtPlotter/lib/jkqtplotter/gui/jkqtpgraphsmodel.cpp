/*
    Copyright (c) 2008-2020 Jan W. Krieger (<jan@jkrieger.de>)



    This software is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License (LGPL) as published by
    the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License (LGPL) for more details.

    You should have received a copy of the GNU Lesser General Public License (LGPL)
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/



#include "jkqtplotter/gui/jkqtpgraphsmodel.h"
#include "jkqtplotter/jkqtpbaseplotter.h"
#include "jkqtplotter/jkqtptools.h"
#include "jkqtplotter/graphs/jkqtpscatter.h"
#include <QImage>



JKQTPGraphsModel::JKQTPGraphsModel(JKQTBasePlotter *parent):
    QAbstractTableModel(parent), m_plotter(parent)
{

}

int JKQTPGraphsModel::rowCount(const QModelIndex &/*parent*/) const
{
    return static_cast<int>(m_plotter->getGraphCount());
}

int JKQTPGraphsModel::columnCount(const QModelIndex &/*parent*/) const
{
    return 1;
}

QVariant JKQTPGraphsModel::data(const QModelIndex &index, int role) const
{
    if (role == Qt::DisplayRole) {
       if (index.row()<static_cast<int>(m_plotter->getGraphCount())) return m_plotter->getGraph(static_cast<size_t>(index.row()))->getTitle();
    } else if (role == Qt::CheckStateRole) {
       if (index.row()<static_cast<int>(m_plotter->getGraphCount())) return m_plotter->getGraph(static_cast<size_t>(index.row()))->isVisible()?Qt::Checked:Qt::Unchecked;
    } else if (role == Qt::DecorationRole) {
        if (index.row()<static_cast<int>(m_plotter->getGraphCount())) {
            return m_plotter->getGraph(static_cast<size_t>(index.row()))->generateKeyMarker(QSize(16,16));
        }
    }
    return QVariant();
}

bool JKQTPGraphsModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (role == Qt::CheckStateRole) {
        if (index.row()<static_cast<int>(m_plotter->getGraphCount())) {
            m_plotter->setGraphVisible(index.row(), value.toBool());
            return true;
        }
    }
    return false;
}

Qt::ItemFlags JKQTPGraphsModel::flags(const QModelIndex &index) const
{
    return Qt::ItemIsUserCheckable | QAbstractTableModel::flags(index);
}

void JKQTPGraphsModel::plotUpdated()
{
    beginResetModel();
    endResetModel();
}

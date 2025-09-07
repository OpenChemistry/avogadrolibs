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



#include "jkqtplotter/graphs/jkqtpspecialline.h"
#include "jkqtplotter/jkqtpbaseplotter.h"
#include <stdlib.h>
#include <QDebug>
#include <iostream>
#include "jkqtplotter/jkqtptools.h"
#include "jkqtplotter/jkqtpimagetools.h"
#include "jkqtplotter/graphs/jkqtpimage.h"
#include "jkqtplotter/jkqtpbaseelements.h"
#include "jkqtplotter/jkqtplotter.h"
#define SmallestGreaterZeroCompare_xvsgz() if ((xvsgz>10.0*DBL_MIN)&&((smallestGreaterZero<10.0*DBL_MIN) || (xvsgz<smallestGreaterZero))) smallestGreaterZero=xvsgz;




JKQTPSpecialLineGraphBase::JKQTPSpecialLineGraphBase(JKQTBasePlotter* parent):
    JKQTPXYBaselineGraph(parent), m_drawSymbols(false), m_specialLineType(JKQTPStepLeft)
{
    parentPlotStyle=-1;
    initLineStyle(parent, parentPlotStyle, JKQTPPlotStyleType::Default);
    initFillStyle(parent, parentPlotStyle, JKQTPPlotStyleType::Default);
    initSymbolStyle(parent, parentPlotStyle, JKQTPPlotStyleType::Default);
    setFillCurve(false);
}

void JKQTPSpecialLineGraphBase::drawKeyMarker(JKQTPEnhancedPainter& painter, QRectF& rect) {
    painter.save(); auto __finalpaint=JKQTPFinally([&painter]() {painter.restore();});
    QPen p=getLinePen(painter, parent);
    QPen np(Qt::NoPen);
    QBrush b=getFillBrush(painter, parent);
    const double y=rect.top()+rect.height()/2.0;
    painter.setPen(np);
    if (getDrawLine()) painter.setPen(p);
    painter.setBrush(b);
    if (getFillCurve()) painter.drawRect(rect);
    if (!getFillCurve() && getDrawLine()) painter.drawLine(QLineF(rect.left(), y, rect.right(), y));
    if (m_drawSymbols) {
        plotStyledSymbol(parent, painter, rect.center().x(), rect.center().y(), rect.width()*0.5);
    }

}


QColor JKQTPSpecialLineGraphBase::getKeyLabelColor() const {
    return getLineColor();
}

void JKQTPSpecialLineGraphBase::setDrawSymbols(bool __value)
{
    m_drawSymbols=__value;
}

bool JKQTPSpecialLineGraphBase::getDrawSymbols() const
{
    return m_drawSymbols;
}


void JKQTPSpecialLineGraphBase::setSpecialLineType(const JKQTPSpecialLineType &__value)
{
    this->m_specialLineType = __value;
}

JKQTPSpecialLineType JKQTPSpecialLineGraphBase::getSpecialLineType() const
{
    return this->m_specialLineType;
}


void JKQTPSpecialLineGraphBase::setColor(QColor c)
{
    setLineColor(c);
    setSymbolColor(c);
    setSymbolFillColor(JKQTPGetDerivedColor(parent->getCurrentPlotterStyle().graphsStyle.defaultGraphStyle.symbolFillColorDerivationMode, c));
    setFillColor(JKQTPGetDerivedColor(parent->getCurrentPlotterStyle().graphsStyle.defaultGraphStyle.fillColorDerivationMode, c));
    c.setAlphaF(0.5);
    setHighlightingLineColor(c);
}



JKQTPSpecialLineHorizontalGraph::JKQTPSpecialLineHorizontalGraph(JKQTBasePlotter* parent):
    JKQTPSpecialLineGraphBase(parent)
{
}


JKQTPSpecialLineHorizontalGraph::JKQTPSpecialLineHorizontalGraph(JKQTPlotter* parent):
    JKQTPSpecialLineHorizontalGraph(parent->getPlotter())
{
}




void JKQTPSpecialLineHorizontalGraph::draw(JKQTPEnhancedPainter& painter) {
#ifdef JKQTBP_AUTOTIMER
    JKQTPAutoOutputTimer jkaaot("JKQTPSpecialLineHorizontalGraph::draw");
#endif
    if (parent==nullptr) return;
    JKQTPDatastore* datastore=parent->getDatastore();
    if (datastore==nullptr) return;

    drawErrorsBefore(painter);

    QPen p=getLinePen(painter, parent);
    QPen ph=getHighlightingLinePen(painter, parent);
    QPen np(Qt::NoPen);
    QBrush b=getFillBrush(painter, parent);

    int imax=0;
    int imin=0;

    if (getIndexRange(imin, imax)) {


        QPainterPath pl, pf;
        QVector<QPointF> ps;

        double xold=-1;
        double yold=-1;
        double y0=transformY(getBaseline());
        if (parent->getYAxis()->isLogAxis()) {
            y0=transformY(parent->getYAxis()->getMin());
            if (getBaseline()>0 && getBaseline()>parent->getYAxis()->getMin()) y0=transformY(getBaseline());
            else y0=transformY(parent->getYAxis()->getMin());
        }
        bool subsequentItem=false;
        intSortData();
        for (int iii=imin; iii<imax; iii++) {
            const int i=qBound(imin, getDataIndex(iii), imax);
            const double xv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i));
            const double yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i));
            //std::cout<<"(xv, yv) =    ( "<<xv<<", "<<yv<<" )\n";
            if (JKQTPIsOKFloat(xv) && JKQTPIsOKFloat(yv)) {
                const double x=transformX(xv);
                const double y=transformY(yv);
                if (JKQTPIsOKFloat(x) && JKQTPIsOKFloat(y)) {
                    ps.append(QPointF(x,y));
                    if (subsequentItem) {
                        //double xl1=xold;
                        //double yl1=yold;
                        //double xl2=x;
                        //double yl2=y;

                        if (m_specialLineType==JKQTPStepCenter) {
                            //                      x/y
                            //              |--------*
                            //              |
                            //     *--------|
                            // xold/yold
                            const double d=(x-xold);
                            pf.lineTo(xold+d/2.0, yold);
                            pf.lineTo(xold+d/2.0, y);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(xold+d/2.0, yold);
                                pl.lineTo(xold+d/2.0, y);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepLeft) {
                            //                     x/y
                            //     |----------------*
                            //     |
                            //     *
                            // xold/yold
                            pf.lineTo(xold, y);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(xold, y);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepRight) {
                            //                     x/y
                            //                      *
                            //                      |
                            //     *----------------|
                            // xold/yold
                            pf.lineTo(x, yold);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(x, yold);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepAverage) {
                            //                     x/y
                            //                      *
                            //                      |
                            //     |----------------|
                            //     |
                            //     *
                            // xold/yold
                            //const double d=(x-xold);
                            const double h=(y-yold);
                            pf.lineTo(xold, yold+h/2.0);
                            pf.lineTo(x, yold+h/2.0);
                            pf.lineTo(x,y);
                            if (getDrawLine()) {
                                pl.lineTo(xold, yold+h/2.0);
                                pl.lineTo(x, yold+h/2.0);
                                pl.lineTo(x,y);
                            }
                        } else if (m_specialLineType==JKQTPDirectLine) {
                            //                     x/y
                            //                 /----*
                            //           /----/
                            //     *----/
                            // xold/yold
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(x, y);
                            }
                        }

                        //std::cout<<"line ("<<xl1<<", "<<yl1<<") -- ("<<xl2<<", "<<yl2<<")"<<std::endl;
                    } else {
                        if (getDrawLine()) pl.moveTo(x,y);
                        pf.moveTo(x, y0);
                        pf.lineTo(x, y);
                        //xstart=x;
                        //ystart=y0;
                    }
                    xold=x;
                    yold=y;
                    subsequentItem=true;
                }
            }
        }
        if (getFillCurve()) {
            pf.lineTo(xold, y0);
            pf.closeSubpath();
        }
        painter.save();
        auto __finalpaint=JKQTPFinally([&painter]() {painter.restore();});

        if (getFillCurve()) {
            painter.fillPath(pf, b);
        }

        if (isHighlighted()) {
            painter.setBrush(QBrush(Qt::transparent));
            painter.setPen(ph);
            painter.drawPath(pl);
        }

        if (getDrawLine()) {
            painter.setBrush(QBrush(Qt::transparent));
            painter.setPen(p);
            painter.drawPath(pl);
        }

        if (m_drawSymbols) {
            painter.save();
            auto __finalpaintsym=JKQTPFinally([&painter]() {painter.restore();});
            for (auto& ppoint: ps) {
                plotStyledSymbol(parent, painter, ppoint.x(), ppoint.y());
            }
        }
    }

    drawErrorsAfter(painter);
}











JKQTPSpecialLineVerticalGraph::JKQTPSpecialLineVerticalGraph(JKQTBasePlotter *parent):
    JKQTPSpecialLineGraphBase(parent)
{
}

JKQTPSpecialLineVerticalGraph::JKQTPSpecialLineVerticalGraph(JKQTPlotter *parent):
    JKQTPSpecialLineVerticalGraph(parent->getPlotter())
{

}

void JKQTPSpecialLineVerticalGraph::draw(JKQTPEnhancedPainter& painter) {
#ifdef JKQTBP_AUTOTIMER
    JKQTPAutoOutputTimer jkaaot("JKQTPSpecialLineVerticalGraph::draw");
#endif
    if (parent==nullptr) return;
    JKQTPDatastore* datastore=parent->getDatastore();
    if (datastore==nullptr) return;

    drawErrorsBefore(painter);

    QPen p=getLinePen(painter, parent);
    QPen ph=getHighlightingLinePen(painter, parent);
    QPen np(Qt::NoPen);
    QBrush b=getFillBrush(painter, parent);

    int imax=0;
    int imin=0;

    if (getIndexRange(imin, imax)) {


        QPainterPath pl, pf;
        QVector<QPointF> ps;

        double xold=-1;
        double yold=-1;
        double x0=transformX(getBaseline());
        if (parent->getXAxis()->isLogAxis()) {
            if (getBaseline()>0 && getBaseline()>parent->getXAxis()->getMin()) x0=transformX(getBaseline());
            else x0=transformX(parent->getXAxis()->getMin());
        }
        bool first=false;
        intSortData();
        for (int iii=imin; iii<imax; iii++) {
            const int i=qBound(imin, getDataIndex(iii), imax);
            const double xv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i));
            const double yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i));
            //std::cout<<"(xv, yv) =    ( "<<xv<<", "<<yv<<" )\n";
            if (JKQTPIsOKFloat(xv) && JKQTPIsOKFloat(yv)) {
                const double x=transformX(xv);
                const double y=transformY(yv);
                if (JKQTPIsOKFloat(x) && JKQTPIsOKFloat(y)) {
                    ps.append(QPointF(x,y));
                    if (first) {
                        //double xl1=xold;
                        //double yl1=yold;
                        //double xl2=x;
                        //double yl2=y;

                        if (m_specialLineType==JKQTPStepCenter) {
                            double d=(y-yold);
                            pf.lineTo(xold, yold+d/2.0);
                            pf.lineTo(x, yold+d/2.0);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(xold, yold+d/2.0);
                                pl.lineTo(x, yold+d/2.0);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepLeft) {
                            pf.lineTo(x, yold);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(x, yold);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepRight) {
                            pf.lineTo(xold, y);
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(xold, y);
                                pl.lineTo(x, y);
                            }
                        } else if (m_specialLineType==JKQTPStepAverage) {
                            //                     x/y
                            //              |-------*
                            //              |
                            //              |
                            //              |
                            //     *--------|
                            // xold/yold
                            const double d=(x-xold);
                            //const double h=(y-yold);
                            pf.lineTo(xold+d/2.0, yold);
                            pf.lineTo(xold+d/2.0, y);
                            pf.lineTo(x,y);
                            if (getDrawLine()) {
                                pl.lineTo(xold+d/2.0, yold);
                                pl.lineTo(xold+d/2.0, y);
                                pl.lineTo(x,y);
                            }
                        } else if (m_specialLineType==JKQTPDirectLine) {
                            //                     x/y
                            //                 /----*
                            //           /----/
                            //     *----/
                            // xold/yold
                            pf.lineTo(x, y);
                            if (getDrawLine()) {
                                pl.lineTo(x, y);
                            }
                        }

                        //std::cout<<"line ("<<xl1<<", "<<yl1<<") -- ("<<xl2<<", "<<yl2<<")"<<std::endl;
                    } else {
                        if (getDrawLine()) pl.moveTo(x,y);
                        pf.moveTo(x0, y);
                        pf.lineTo(x, y);
                    }
                    xold=x;
                    yold=y;
                    first=true;
                }
            }
        }
        pf.lineTo(x0, yold);
        pf.closeSubpath();
        painter.save(); auto __finalpaint=JKQTPFinally([&painter]() {painter.restore();});

        if (getFillCurve()) {
            painter.fillPath(pf, b);
        }

        if (isHighlighted()) {
            painter.setBrush(QBrush(Qt::transparent));
            painter.setPen(ph);
            painter.drawPath(pl);
        }

        if (getDrawLine()) {
            painter.setBrush(QBrush(Qt::transparent));
            painter.setPen(p);
            painter.drawPath(pl);
        }

        if (m_drawSymbols) {
            painter.save();
            auto __finalpaintsym=JKQTPFinally([&painter]() {painter.restore();});
            for (auto& point: ps) {
                plotStyledSymbol(parent, painter, point.x(), point.y());
            }
        }
    }

    drawErrorsAfter(painter);
}

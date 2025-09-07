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



#include "jkqtplotter/graphs/jkqtpbarchart.h"
#include "jkqtplotter/jkqtpbaseplotter.h"
#include <stdlib.h>
#include <QDebug>
#include <iostream>
#include "jkqtplotter/jkqtptools.h"
#include "jkqtplotter/graphs/jkqtpimage.h"
#include "jkqtplotter/jkqtpbaseelements.h"
#include "jkqtplotter/jkqtplotter.h"

#define SmallestGreaterZeroCompare_xvsgz() if ((xvsgz>10.0*DBL_MIN)&&((smallestGreaterZero<10.0*DBL_MIN) || (xvsgz<smallestGreaterZero))) smallestGreaterZero=xvsgz;






JKQTPBarVerticalGraph::JKQTPBarVerticalGraph(JKQTBasePlotter* parent):
    JKQTPBarGraphBase(parent)
{

}


JKQTPBarVerticalGraph::JKQTPBarVerticalGraph(JKQTPlotter* parent):
    JKQTPBarVerticalGraph(parent->getPlotter())
{
}

void JKQTPBarVerticalGraph::draw(JKQTPEnhancedPainter& painter) {
#ifdef JKQTBP_AUTOTIMER
    JKQTPAutoOutputTimer jkaaot("JKQTPBarHorizontalGraph::draw");
#endif
    if (parent==nullptr) return;
    const JKQTPDatastore* datastore=parent->getDatastore();
    if (datastore==nullptr) return;

    drawErrorsBefore(painter);

    const QPen p=getLinePenForRects(painter, parent);
    const QBrush b=getFillBrush(painter, parent);

    int imax=0;
    int imin=0;
    if (getIndexRange(imin, imax)) {
        painter.save(); auto __finalpaint=JKQTPFinally([&painter]() {painter.restore();});

    //    double x0=transformX(0);
    //    if (parent->getXAxis()->isLogAxis()) x0=transformX(parent->getXAxis()->getMin());
        double y0=transformY(0);
        if (parent->getYAxis()->isLogAxis()) y0=transformY(parent->getYAxis()->getMin());
        double delta=1;
        double deltap=0;
        double deltam=0;
        intSortData();
        const bool hasStackPar=hasStackParent();
        for (int iii=imin; iii<imax; iii++) {
            int i=qBound(imin, getDataIndex(iii), imax);
            const double xv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i));
            const int sr=datastore->getNextLowerIndex(xColumn, i);
            const int lr=datastore->getNextHigherIndex(xColumn, i);
            double yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i));
            double yv0=y0;
            if (!qFuzzyIsNull(getBaseline())) yv0=transformY(getBaseline());
            if (hasStackPar) {
                double stackLastY=getParentStackedMax(i);
                const double yvold=yv;
                yv0=transformY(stackLastY)-(getLineWidth());
                yv=stackLastY+yvold;
            }
            if (sr<0 && lr<0) { // only one x-value
                deltam=0.5;
                deltap=0.5;
            } else if (lr<0) { // the right-most x-value
                deltap=deltam=fabs(xv-datastore->get(xColumn,sr))/2.0;
            } else if (sr<0) { // the left-most x-value
                deltam=deltap=fabs(datastore->get(xColumn,lr)-xv)/2.0;
            } else {
                deltam=fabs(xv-datastore->get(xColumn,sr))/2.0;
                deltap=fabs(datastore->get(xColumn,lr)-xv)/2.0;
            }
            //std::cout<<iii<<", \t"<<i<<", \t"<<sr<<", \t"<<lr<<", \t"<<deltam<<", \t"<<deltap<<"\n\n";
            delta=deltap+deltam;

            if (JKQTPIsOKFloat(xv) && JKQTPIsOKFloat(yv)) {
                const double x=transformX(xv+shift*delta-width*deltam);
                double y=transformY(yv);
                const double xx=transformX(xv+shift*delta+width*deltap);
                double yy=yv0;

                //std::cout<<"delta="<<delta<<"   x="<<x<<" y="<<y<<"   xx="<<xx<<" yy="<<yy<<std::endl;
                if (yy<y) { qSwap(y,yy); }
                if (JKQTPIsOKFloat(x) && JKQTPIsOKFloat(xx) && JKQTPIsOKFloat(y) && JKQTPIsOKFloat(yy)) {
                    painter.setBrush(b);
                    painter.setPen(p);
                    QRectF r(QPointF(x, y), QPointF(xx, yy));
                    painter.drawRect(r);

                }
            }
        }

    }
    drawErrorsAfter(painter);
}

bool JKQTPBarVerticalGraph::getXMinMax(double& minx, double& maxx, double& smallestGreaterZero) {
    return getPositionsMinMax(minx, maxx, smallestGreaterZero);
}

bool JKQTPBarVerticalGraph::getYMinMax(double& miny, double& maxy, double& smallestGreaterZero) {
    return getValuesMinMax(miny, maxy, smallestGreaterZero);
}

int JKQTPBarVerticalGraph::getBarPositionColumn() const
{
    return xColumn;
}

int JKQTPBarVerticalGraph::getBarHeightColumn() const
{
    return yColumn;
}

void JKQTPBarVerticalGraph::setBarPositionColumn(int column)
{
    xColumn=column;
}

void JKQTPBarVerticalGraph::setBarPositionColumn(size_t column)
{
    xColumn=column;
}

void JKQTPBarVerticalGraph::setBarHeightColumn(int column)
{
    yColumn=column;
}

void JKQTPBarVerticalGraph::setBarHeightColumn(size_t column)
{
    yColumn=column;
}

bool JKQTPBarVerticalGraph::considerForAutoscaling(JKQTPBarGraphBase *other) const
{
    return (dynamic_cast<JKQTPBarVerticalGraph*>(other)!=nullptr);
}










JKQTPBarHorizontalGraph::JKQTPBarHorizontalGraph(JKQTBasePlotter *parent):
    JKQTPBarGraphBase(parent)
{

}

JKQTPBarHorizontalGraph::JKQTPBarHorizontalGraph(JKQTPlotter *parent):
    JKQTPBarHorizontalGraph(parent->getPlotter())
{

}

int JKQTPBarHorizontalGraph::getBarPositionColumn() const
{
    return yColumn;
}

int JKQTPBarHorizontalGraph::getBarHeightColumn() const
{
    return xColumn;
}

void JKQTPBarHorizontalGraph::setBarPositionColumn(int column)
{
    yColumn=column;
}

void JKQTPBarHorizontalGraph::setBarPositionColumn(size_t column)
{
    yColumn=column;
}

void JKQTPBarHorizontalGraph::setBarHeightColumn(int column)
{
    xColumn=column;
}

void JKQTPBarHorizontalGraph::setBarHeightColumn(size_t column)
{
    xColumn=column;
}

bool JKQTPBarHorizontalGraph::considerForAutoscaling(JKQTPBarGraphBase *other) const
{
    return (dynamic_cast<JKQTPBarHorizontalGraph*>(other)!=nullptr);
}

void JKQTPBarHorizontalGraph::draw(JKQTPEnhancedPainter& painter) {
#ifdef JKQTBP_AUTOTIMER
    JKQTPAutoOutputTimer jkaaot("JKQTPBarVerticalGraph::draw");
#endif
    if (parent==nullptr) return;
    const JKQTPDatastore* datastore=parent->getDatastore();
    if (datastore==nullptr) return;

    drawErrorsBefore(painter);

    const QPen p=getLinePenForRects(painter, parent);
    const QBrush b=getFillBrush(painter, parent);

    int imax=0;
    int imin=0;
    if (getIndexRange(imin, imax)) {

        double x0=transformX(0);
        if (parent->getXAxis()->isLogAxis()) x0=transformX(parent->getXAxis()->getMin());
    //    double y0=transformY(0);
    //    if (parent->getYAxis()->isLogAxis()) y0=transformY(parent->getYAxis()->getMin());
        {
            painter.save(); auto __finalpaint=JKQTPFinally([&painter]() {painter.restore();});
            intSortData();
            const bool hasStackPar=hasStackParent();
            double delta=1;
            double deltap=0;
            double deltam=0;
            for (int iii=imin; iii<imax; iii++) {
                int i=qBound(imin, getDataIndex(iii), imax);
                double xv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i));
                double yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i));
                int sr=datastore->getNextLowerIndex(yColumn, i);
                int lr=datastore->getNextHigherIndex(yColumn, i);
                double xv0=x0;
                if (!qFuzzyIsNull(getBaseline())) xv0=transformX(getBaseline());
                if (hasStackPar) {
                    double stackLastX=getParentStackedMax(i);
                    const double xvold=xv;
                    xv0=transformX(stackLastX)+(getLineWidth());
                    xv=stackLastX+xvold;
                }


                if (sr<0 && lr<0) { // only one y-value
                    deltam=0.5;
                    deltap=0.5;
                } else if (lr<0) { // the right-most y-value
                    deltap=deltam=fabs(yv-datastore->get(yColumn,sr))/2.0;
                } else if (sr<0) { // the left-most y-value
                    deltam=deltap=fabs(datastore->get(yColumn,lr)-yv)/2.0;
                } else {
                    deltam=fabs(yv-datastore->get(yColumn,sr))/2.0;
                    deltap=fabs(datastore->get(yColumn,lr)-yv)/2.0;
                }
                delta=deltap+deltam;

                if (JKQTPIsOKFloat(xv) && JKQTPIsOKFloat(yv)) {
                    double x=xv0;
                    if (!qFuzzyIsNull(getBaseline())) x=transformX(getBaseline());
                    double y=transformY(yv+shift*delta+width*deltap);
                    double xx=transformX(xv);
                    double yy=transformY(yv+shift*delta-width*deltam);
                    if (x>xx) { qSwap(x,xx); }
                    //qDebug()<<"delta="<<delta<<"   x="<<x<<" y="<<y<<"   xx="<<xx<<" yy="<<yy;
                    //qDebug()<<"xv="<<xv<<"   x0="<<x0<<"   x="<<x<<"..."<<xx;
                    if (JKQTPIsOKFloat(x) && JKQTPIsOKFloat(xx) && JKQTPIsOKFloat(y) && JKQTPIsOKFloat(yy)) {
                        painter.setBrush(b);
                        painter.setPen(p);
                        QRectF r(QPointF(x, y), QPointF(xx, yy));
                        painter.drawRect(r);
                    }
                }
            }
        }
    }
    drawErrorsAfter(painter);
}

bool JKQTPBarHorizontalGraph::getXMinMax(double& minx, double& maxx, double& smallestGreaterZero) {
    return getValuesMinMax(minx, maxx, smallestGreaterZero);
}

bool JKQTPBarHorizontalGraph::getYMinMax(double& miny, double& maxy, double& smallestGreaterZero) {
    return getPositionsMinMax(miny, maxy, smallestGreaterZero);

}





JKQTPBarHorizontalErrorGraph::JKQTPBarHorizontalErrorGraph(JKQTBasePlotter *parent):
    JKQTPBarHorizontalGraph(parent)
{
    setErrorColorFromGraphColor(getKeyLabelColor());
    initErrorStyle(parent, parentPlotStyle, JKQTPPlotStyleType::Barchart);
}

JKQTPBarHorizontalErrorGraph::JKQTPBarHorizontalErrorGraph(JKQTPlotter *parent):
    JKQTPBarHorizontalErrorGraph(parent->getPlotter())
{

}

bool JKQTPBarHorizontalErrorGraph::usesColumn(int c) const
{
    return JKQTPBarHorizontalGraph::usesColumn(c)|| JKQTPXGraphErrors::errorUsesColumn(c);
}

bool JKQTPBarHorizontalErrorGraph::getXMinMax(double &minx, double &maxx, double &smallestGreaterZero)
{
    if (xErrorColumn<0 || xErrorStyle==JKQTPNoError) {
        return JKQTPBarHorizontalGraph::getXMinMax(minx, maxx, smallestGreaterZero);
    } else {
        bool start=false;
        minx=0;
        maxx=0;
        smallestGreaterZero=0;

        if (parent==nullptr) return false;

        const JKQTPDatastore* datastore=parent->getDatastore();
        int imax=0;
        int imin=0;
        if (getIndexRange(imin, imax)) {

            for (int i=imin; i<imax; i++) {
                double xvsgz;
                const double xv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i))+getXErrorU(i, datastore);
                const double xvv=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(i))-getXErrorL(i, datastore);
                if (JKQTPIsOKFloat(xv) && JKQTPIsOKFloat(xvv) ) {
                    if (start || xv>maxx) maxx=xv;
                    if (start || xv<minx) minx=xv;
                    xvsgz=xv; SmallestGreaterZeroCompare_xvsgz();
                    start=false;
                    if (xvv>maxx) maxx=xvv;
                    if (xvv<minx) minx=xvv;
                    xvsgz=xvv; SmallestGreaterZeroCompare_xvsgz();
                    start=false;
                }
            }
            return !start;
        }
        return false;
    }
}

void JKQTPBarHorizontalErrorGraph::drawErrorsAfter(JKQTPEnhancedPainter &painter)
{
    if (sortData==JKQTPXYGraph::Unsorted) plotErrorIndicators(painter, parent, this, xColumn, yColumn, 0.0, shift);
    else plotErrorIndicators(painter, parent, this, xColumn, yColumn, 0.0, shift, &sortedIndices);
}



int JKQTPBarHorizontalErrorGraph::getBarErrorColumn() const
{
    return getXErrorColumn();
}

int JKQTPBarHorizontalErrorGraph::getBarLowerErrorColumn() const
{
    return getXErrorColumnLower();
}

void JKQTPBarHorizontalErrorGraph::setBarErrorColumn(int column)
{
    setXErrorColumn(column);
}

void JKQTPBarHorizontalErrorGraph::setBarErrorColumn(size_t column)
{
    setXErrorColumn(column);
}

void JKQTPBarHorizontalErrorGraph::setBarLowerErrorColumn(int column)
{
    setXErrorColumnLower(column);
}

void JKQTPBarHorizontalErrorGraph::setBarLowerErrorColumn(size_t column)
{
    setXErrorColumnLower(column);
}

JKQTPBarVerticalErrorGraph::JKQTPBarVerticalErrorGraph(JKQTBasePlotter *parent):
    JKQTPBarVerticalGraph(parent)
{
    setErrorColorFromGraphColor(getKeyLabelColor());
    initErrorStyle(parent, parentPlotStyle, JKQTPPlotStyleType::Barchart);

}

JKQTPBarVerticalErrorGraph::JKQTPBarVerticalErrorGraph(JKQTPlotter *parent):
    JKQTPBarVerticalErrorGraph(parent->getPlotter())
{

}

bool JKQTPBarVerticalErrorGraph::usesColumn(int c) const
{
    return JKQTPBarVerticalGraph::usesColumn(c)|| JKQTPYGraphErrors::errorUsesColumn(c);
}

bool JKQTPBarVerticalErrorGraph::getYMinMax(double &miny, double &maxy, double &smallestGreaterZero)
{
    if (yErrorColumn<0 || yErrorStyle==JKQTPNoError) {
        miny=0;
        maxy=0;
        smallestGreaterZero=0;
        if (getBaseline()>0) {
            smallestGreaterZero=getBaseline();
            miny=getBaseline();
            maxy=getBaseline();
        }

        if (parent==nullptr) return false;

        JKQTPDatastore* datastore=parent->getDatastore();
        int imax=0;
        int imin=0;
        if (getIndexRange(imin, imax)) {


            for (int i=imin; i<imax; i++) {
                double yv=getBaseline();
                if (JKQTPIsOKFloat(yv)) {
                    if (yv>maxy) maxy=yv;
                    if (yv<miny) miny=yv;
                    double xvsgz;
                    xvsgz=yv; SmallestGreaterZeroCompare_xvsgz();
                }
                yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i));
                if (JKQTPIsOKFloat(yv)) {
                    if (yv>maxy) maxy=yv;
                    if (yv<miny) miny=yv;
                    double xvsgz;
                    xvsgz=yv; SmallestGreaterZeroCompare_xvsgz();
                }
            }
            return true;
        }
    } else {
        bool start=false;
        miny=getBaseline();
        maxy=getBaseline();
        smallestGreaterZero=0;
        if (getBaseline()>0) {
            smallestGreaterZero=getBaseline();
            miny=getBaseline();
            maxy=getBaseline();
        }

        if (parent==nullptr) return false;

        const JKQTPDatastore* datastore=parent->getDatastore();
        int imax=0;
        int imin=0;
        if (getIndexRange(imin, imax)) {


            for (int i=imin; i<imax; i++) {
                const double yv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i))+getYErrorU(i, datastore);
                const double yvv=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(i))-getYErrorL(i, datastore);
                if (JKQTPIsOKFloat(yv) && JKQTPIsOKFloat(yvv) ) {
                    if (start || yv>maxy) maxy=yv;
                    if (start || yv<miny) miny=yv;
                    double xvsgz;
                    xvsgz=yv; SmallestGreaterZeroCompare_xvsgz();
                    if (start || yvv>maxy) maxy=yvv;
                    if (start || yvv<miny) miny=yvv;
                    xvsgz=yvv; SmallestGreaterZeroCompare_xvsgz();
                    start=false;
                }
            }
            return !start;
        }
    }
    return false;
}

int JKQTPBarVerticalErrorGraph::getBarErrorColumn() const
{
    return getYErrorColumn();
}

int JKQTPBarVerticalErrorGraph::getBarLowerErrorColumn() const
{
    return getYErrorColumnLower();
}

void JKQTPBarVerticalErrorGraph::setBarErrorColumn(int column)
{
    setYErrorColumn(column);
}

void JKQTPBarVerticalErrorGraph::setBarErrorColumn(size_t column)
{
    setYErrorColumn(column);
}

void JKQTPBarVerticalErrorGraph::setBarLowerErrorColumn(int column)
{
    setYErrorColumnLower(column);
}

void JKQTPBarVerticalErrorGraph::setBarLowerErrorColumn(size_t column)
{
    setYErrorColumnLower(column);
}

void JKQTPBarVerticalErrorGraph::drawErrorsAfter(JKQTPEnhancedPainter &painter)
{
    //plotErrorIndicators(painter, parent, this, xColumn, yColumn, shift, 0.0);
    if (sortData==JKQTPXYGraph::Unsorted) plotErrorIndicators(painter, parent, this, xColumn, yColumn, shift, 0.0);
    else plotErrorIndicators(painter, parent, this, xColumn, yColumn, shift, 0, &sortedIndices);
}












JKQTPBarVerticalStackableGraph::JKQTPBarVerticalStackableGraph(JKQTBasePlotter *parent):
    JKQTPBarVerticalGraph(parent), stackParent(nullptr)
{

}

JKQTPBarVerticalStackableGraph::JKQTPBarVerticalStackableGraph(JKQTPlotter *parent):
    JKQTPBarVerticalStackableGraph(parent->getPlotter())
{

}

void JKQTPBarVerticalStackableGraph::stackUpon(JKQTPBarVerticalStackableGraph *parentGraph)
{
    stackParent=parentGraph;
}

void JKQTPBarVerticalStackableGraph::dontStackUpon()
{
    stackParent=nullptr;
}

double JKQTPBarVerticalStackableGraph::getParentStackedMax(int index) const
{
    if (stackParent) {
        return stackParent->getStackedMax(index);
    } else {
        return getBaseline();
    }
}

bool JKQTPBarVerticalStackableGraph::hasStackParent() const
{
    return stackParent!=nullptr;
}

const JKQTPBarVerticalStackableGraph *JKQTPBarVerticalStackableGraph::getStackParent() const
{
    return stackParent;
}

JKQTPBarVerticalStackableGraph *JKQTPBarVerticalStackableGraph::getStackParent()
{
    return stackParent;
}

double JKQTPBarVerticalStackableGraph::getStackedMax(int index) const
{
    double height=0;
    if (parent!=nullptr) {
        JKQTPDatastore* datastore=parent->getDatastore();
        height=datastore->get(static_cast<size_t>(yColumn),static_cast<size_t>(index));
    }
    if (stackParent==nullptr) {
        return height;
    } else {
        return stackParent->getStackedMax(index)+height;
    }
}

JKQTPBarHorizontalStackableGraph::JKQTPBarHorizontalStackableGraph(JKQTBasePlotter *parent):
    JKQTPBarHorizontalGraph(parent), stackParent(nullptr)
{

}

JKQTPBarHorizontalStackableGraph::JKQTPBarHorizontalStackableGraph(JKQTPlotter *parent):
    JKQTPBarHorizontalStackableGraph(parent->getPlotter())
{

}

void JKQTPBarHorizontalStackableGraph::stackUpon(JKQTPBarHorizontalStackableGraph *parentGraph)
{
    stackParent=parentGraph;
}

void JKQTPBarHorizontalStackableGraph::dontStackUpon()
{
    stackParent=nullptr;
}

const JKQTPBarHorizontalStackableGraph *JKQTPBarHorizontalStackableGraph::getStackParent() const
{
    return stackParent;
}

JKQTPBarHorizontalStackableGraph *JKQTPBarHorizontalStackableGraph::getStackParent()
{
    return stackParent;
}


double JKQTPBarHorizontalStackableGraph::getStackedMax(int index) const
{
    double height=0;
    if (parent!=nullptr) {
        JKQTPDatastore* datastore=parent->getDatastore();
        height=datastore->get(static_cast<size_t>(xColumn),static_cast<size_t>(index));
    }
    if (stackParent==nullptr) {
        return height;
    } else {
        return stackParent->getStackedMax(index)+height;
    }
}

double JKQTPBarHorizontalStackableGraph::getParentStackedMax(int index) const
{
    if (stackParent) {
        return stackParent->getStackedMax(index);
    } else {
        return getBaseline();
    }
}

bool JKQTPBarHorizontalStackableGraph::hasStackParent() const
{
    return stackParent!=nullptr;
}

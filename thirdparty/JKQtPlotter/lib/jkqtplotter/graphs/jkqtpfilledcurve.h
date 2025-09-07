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

#ifndef jkqtpgraphsfilledcurve_H
#define jkqtpgraphsfilledcurve_H


#include "jkqtplotter/jkqtplotter_imexport.h"
#include "jkqtplotter/jkqtpgraphsbase.h"
#include "jkqtplotter/jkqtpgraphsbaseerrors.h"
#include "jkqtplotter/graphs/jkqtpspecialline.h"





/** \brief a Base class for filled curve graphs like e.g. JKQTPFilledCurveXGraph
 *  \ingroup jkqtplotter_linesymbolgraphs_simple
 *
 *  \image html filledgraphs.png
 *
 *  \see JKQTPFilledCurveXGraph, JKQTPFilledCurveYGraph
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledCurveGraphBase: public JKQTPXYBaselineGraph, public JKQTPGraphLineAndFillStyleMixin {
    Q_OBJECT
public:
    /** \brief class constructor */
    explicit JKQTPFilledCurveGraphBase(JKQTBasePlotter* parent=nullptr);

    /** \brief returns the color to be used for the key label */
    virtual QColor getKeyLabelColor() const override;
    /** \brief plots a key marker inside the specified rectangle \a rect */
    virtual void drawKeyMarker(JKQTPEnhancedPainter& painter, QRectF& rect) override;

public slots:
    /** \brief set line-color, fill color and symbol color */
    void setColor(QColor c);
protected:

};



/*! \brief This implements filled curve plots where the area is filled between the plot line and the x-Axis.
    \ingroup jkqtplotter_filledgraphs

    \image html filledgraphs.png

    \see \ref JKQTPlotterFilledGraphs
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledCurveXGraph: public JKQTPFilledCurveGraphBase {
        Q_OBJECT
    public:
        /** \brief class constructor */
        JKQTPFilledCurveXGraph(JKQTBasePlotter* parent=nullptr);
        /** \brief class constructor */
        JKQTPFilledCurveXGraph(JKQTPlotter* parent);
        /** \brief plots the graph to the plotter object specified as parent */
        void draw(JKQTPEnhancedPainter &painter);
};



/*! \brief This implements filled curve plots with y errors where the area is filled between the plot line and the x-Axis.
    \ingroup jkqtplotter_filledgraphs

    \image html plot_filledcurvexerrorplots.png


    \see \ref JKQTPlotterFilledGraphs, jkqtpstatAddXErrorFilledCurveGraph()
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledCurveXErrorGraph: public JKQTPFilledCurveXGraph, public JKQTPYGraphErrors {
        Q_OBJECT
    public:
        /** \brief class constructor */
        JKQTPFilledCurveXErrorGraph(JKQTBasePlotter* parent=nullptr);
        /** \brief class constructor */
        JKQTPFilledCurveXErrorGraph(JKQTPlotter* parent);
        /** \copydoc JKQTPGraph::usesColumn() */
        virtual bool usesColumn(int c) const override;

    protected:
        /** \brief this function is used to plot error inidcators before plotting the graphs. */
        virtual void drawErrorsAfter(JKQTPEnhancedPainter& painter) override;

};






/*! \brief This implements filled curve plots where the area is filled between the plot line and y-Axis
    \ingroup jkqtplotter_filledgraphs

    \image html filledgraphs_yaxis.png

    \see \ref JKQTPlotterFilledGraphs

 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledCurveYGraph: public JKQTPFilledCurveGraphBase {
        Q_OBJECT
    public:
        /** \brief class constructor */
        JKQTPFilledCurveYGraph(JKQTBasePlotter* parent=nullptr);
        /** \brief class constructor */
        JKQTPFilledCurveYGraph(JKQTPlotter* parent);

        /** \brief plots the graph to the plotter object specified as parent */
        void draw(JKQTPEnhancedPainter &painter);

};



/*! \brief This implements filled curve plots with y errors where the area is filled between the plot line and the x-Axis.
    \ingroup jkqtplotter_filledgraphs

    \image html plot_filledcurveyerrorplots.png

    \see \ref JKQTPlotterFilledGraphs, jkqtpstatAddYErrorFilledCurveGraph()
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledCurveYErrorGraph: public JKQTPFilledCurveYGraph, public JKQTPXGraphErrors {
        Q_OBJECT
    public:
        /** \brief class constructor */
        JKQTPFilledCurveYErrorGraph(JKQTBasePlotter* parent=nullptr);
        JKQTPFilledCurveYErrorGraph(JKQTPlotter* parent);
        /** \copydoc JKQTPGraph::usesColumn() */
        virtual bool usesColumn(int c) const override;

    protected:
        /** \brief this function is used to plot error inidcators before plotting the graphs. */
        virtual void drawErrorsAfter(JKQTPEnhancedPainter& painter) override;

};







/** \brief This implements filled curve plots where the area is filled between two data columns for each x-value
  * \ingroup jkqtplotter_filledgraphs
  *
  * With \c setDrawlines(false):
  *
  * \image html JKQTPfilledVerticalRangeGraph.png
  *
  * With \c setDrawlines(true):
  *
  * \image html JKQTPfilledVerticalRangeGraph_WithLines.png
  *
  * \see JKQTPFilledHorizontalRangeGraph, \ref JKQTPlotterDateTimeAxes
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledVerticalRangeGraph: public JKQTPXYYGraph, public JKQTPGraphLineAndFillStyleMixin {
    Q_OBJECT
public:
    /** \brief class constructor */
    JKQTPFilledVerticalRangeGraph(JKQTBasePlotter* parent=nullptr);
    /** \brief class constructor */
    JKQTPFilledVerticalRangeGraph(JKQTPlotter* parent);

    /** \brief plots the graph to the plotter object specified as parent */
    virtual void draw(JKQTPEnhancedPainter& painter) override;
    /** \brief plots a key marker inside the specified rectangle \a rect */
    virtual void drawKeyMarker(JKQTPEnhancedPainter& painter, QRectF& rect) override;
    /** \brief returns the color to be used for the key label */
    virtual QColor getKeyLabelColor() const override;


protected:


};







/** \brief This implements filled curve plots where the area is filled between two data columns for each y-value
  * \ingroup jkqtplotter_filledgraphs
  *
  * With \c setDrawlines(false):
  *
  * \image html JKQTPFilledHorizontalRangeGraph.png
  *
  * With \c setDrawlines(true):
  *
  * \image html JKQTPFilledHorizontalRangeGraph_WithLines.png
  *
  * \see JKQTPFilledVerticalRangeGraph, \ref JKQTPlotterDateTimeAxes
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPFilledHorizontalRangeGraph: public JKQTPXXYGraph, public JKQTPGraphLineAndFillStyleMixin {
    Q_OBJECT
public:
    /** \brief class constructor */
    JKQTPFilledHorizontalRangeGraph(JKQTBasePlotter* parent=nullptr);
    /** \brief class constructor */
    JKQTPFilledHorizontalRangeGraph(JKQTPlotter* parent);

    /** \brief plots the graph to the plotter object specified as parent */
    virtual void draw(JKQTPEnhancedPainter& painter) override;
    /** \brief plots a key marker inside the specified rectangle \a rect */
    virtual void drawKeyMarker(JKQTPEnhancedPainter& painter, QRectF& rect) override;
    /** \brief returns the color to be used for the key label */
    virtual QColor getKeyLabelColor() const override;


protected:


};


#endif // jkqtpgraphsfilledcurve_H

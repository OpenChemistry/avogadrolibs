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


#ifndef jkqtpgraphsbasestylingmixins_H
#define jkqtpgraphsbasestylingmixins_H


#include <QString>
#include <QPainter>
#include <QPen>
#include <QBrush>
#include "jkqtplotter/jkqtptools.h"
#include "jkqtplotter/jkqtplotter_imexport.h"
#include "jkqtplotter/jkqtpbaseplotter.h"
#include "jkqtcommon/jkqtpdrawingtools.h"


class JKQTPlotter; // forward


/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph line style
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
      - line color
      - line width
      - line style (including custom dash patterns, as in QPen)
      - line color, when graph is highlighted
    .
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphLineStyleMixin {
        Q_GADGET
    public:
        /** \brief class constructor */
        JKQTPGraphLineStyleMixin();
        /** \brief initiaize the line style (from the parent plotter) */
        void initLineStyle(JKQTBasePlotter *parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

        virtual ~JKQTPGraphLineStyleMixin();

        /** \brief set the color of the graph line */
        void setLineColor(const QColor & __value);
        /** \brief get the color of the graph line */
        QColor getLineColor() const;

        /** \brief set the style of the graph line */
        void setLineStyle(Qt::PenStyle __value);
        /** \brief get the style of the graph line */
        Qt::PenStyle getLineStyle() const;

        /** \brief set the line width of the graph line (in pt) */
        void setLineWidth(double __value);
        /** \brief get the line width of the graph line (in pt) */
        double getLineWidth() const;

        /** \brief sets the dash offset for a custom dash style
         *  \see https://doc.qt.io/qt-5/qpen.html#setDashOffset
         */
        void setLineDashOffset(qreal offset);
        /** \brief returns the dash offset for a custom dash style
         *  \see https://doc.qt.io/qt-5/qpen.html#setDashOffset
         */
        qreal getLineDashOffset() const;
        /** \brief sets the dash pattern for a custom dash style
         *  \see https://doc.qt.io/qt-5/qpen.html#setDashPattern
         */
        void setLineDashPattern(const QVector<qreal> &pattern);
        /** \brief gets the dash pattern for a custom dash style
         *  \see https://doc.qt.io/qt-5/qpen.html#setDashPattern
         */
        QVector<qreal> getLineDashPattern() const;
        /** \brief sets the join style
         *  \see https://doc.qt.io/qt-5/qpen.html#setJoinStyle
         */
        void setLineJoinStyle(Qt::PenJoinStyle style);
        /** \brief returns the join style
         *  \see https://doc.qt.io/qt-5/qpen.html#setJoinStyle
         */
        Qt::PenJoinStyle getLineJoinStyle() const;
        /** \brief sets the cap style
         *  \see https://doc.qt.io/qt-5/qpen.html#setCapStyle
         */
        void setLineCapStyle(Qt::PenCapStyle style);
        /** \brief gets the cap style
         *  \see https://doc.qt.io/qt-5/qpen.html#setCapStyle
         */
        Qt::PenCapStyle getLineCapStyle() const;
        /** \brief sets the brush used to fill the line area
         *  \see https://doc.qt.io/qt-5/qpen.html#setBrush
         */
        void setLineBrush(const QBrush& style);
        /** \brief gets the brush used to fill the line area
         *  \see https://doc.qt.io/qt-5/qpen.html#setBrush
         */
        QBrush getLineBrush() const;


        /** \brief set the color of the graph line when highlighted */
        void setHighlightingLineColor(const QColor & __value);
        /** \brief get the color of the graph line when highlighted */
        QColor getHighlightingLineColor() const;


        Q_PROPERTY(QColor highlightingLineColor MEMBER m_highlightingLineColor READ getHighlightingLineColor WRITE setHighlightingLineColor)
        Q_PROPERTY(QColor lineColor MEMBER m_lineColor READ getLineColor WRITE setLineColor)
        Q_PROPERTY(Qt::PenStyle lineStyle MEMBER m_lineStyle READ getLineStyle WRITE setLineStyle)
        Q_PROPERTY(double lineWidth MEMBER m_lineWidth READ getLineWidth WRITE setLineWidth)
    private:
        /** \brief graph line pen */
        QPen m_linePen;
        /** \brief width of the graph lines, given in pt */
        double m_lineWidth;
        /** \brief line pen for the highlighted look */
        QColor m_highlightingLineColor;
    protected:
        /** \brief constructs a QPen from the line styling properties */
        QPen getLinePen(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
        /** \brief constructs a QPen from the line styling properties, suitable for drawing rectangles with sharp edges */
        QPen getLinePenForRects(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
        /** \brief constructs a QPen from the line styling properties */
        QPen getHighlightingLinePen(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
        /** \brief constructs a QPen from the line styling properties, suitable for drawing rectangle with sharp corners */
        QPen getHighlightingLinePenForRects(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
};






/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph line style of lines
           with a decorator (i.e. an arrow) at their head. It extends JKQTPGraphLineStyleMixin
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
        - head/ arrow style
    .

    \see JKQTPGraphDecoratedLineStyleMixin for a Mix-In for both ends
*/
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphDecoratedHeadLineStyleMixin: public JKQTPGraphLineStyleMixin {
    Q_GADGET
public:
    /** \brief class constructor */
    JKQTPGraphDecoratedHeadLineStyleMixin();
    /** \brief initiaize the line style (from the parent plotter) */
    void initDecoratedHeadLineStyle(JKQTBasePlotter *parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

    virtual ~JKQTPGraphDecoratedHeadLineStyleMixin();

    /** \brief set the head decorator style */
    void setHeadDecoratorStyle(const JKQTPLineDecoratorStyle & __value);
    /** \brief get the head decorator style */
    JKQTPLineDecoratorStyle getHeadDecoratorStyle() const;

    /** \copydoc m_headDecoratorSizeFactor */
    void setHeadDecoratorSizeFactor(const double & __value);
    /** \copydoc m_headDecoratorSizeFactor */
    double getHeadDecoratorSizeFactor() const;

    /** \brief calculates the tail decorator size from the line width \a line_width, using m_headDecoratorSizeFactor and a non-linear scaling function
     *
     *  \see JKQTPLineDecoratorStyleCalcDecoratorSize()
     */
    double calcHeadDecoratorSize(double line_width) const;



    Q_PROPERTY(JKQTPLineDecoratorStyle headDecoratorStyle MEMBER m_headDecoratorStyle READ getHeadDecoratorStyle WRITE setHeadDecoratorStyle)
    Q_PROPERTY(double headDecoratorSizeFactor MEMBER m_headDecoratorSizeFactor READ getHeadDecoratorSizeFactor WRITE setHeadDecoratorSizeFactor)
private:
    /** \brief head decorator style */
    JKQTPLineDecoratorStyle m_headDecoratorStyle;
    /** \brief head decorator size-factor, used to calculate the size of the arrow from the line width */
    double m_headDecoratorSizeFactor;
};





/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph line style of lines
           with decorators (i.e. arrows) at their ends. It extends JKQTPGraphLineStyleMixin
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
        - head/tail arrow style
    .

    \see JKQTPGraphDecoratedHeadLineStyleMixin for a Mix-In for one end (head) only
*/
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphDecoratedLineStyleMixin: public JKQTPGraphLineStyleMixin {
    Q_GADGET
public:
    /** \brief class constructor */
    JKQTPGraphDecoratedLineStyleMixin();
    /** \brief initiaize the line style (from the parent plotter) */
    void initDecoratedLineStyle(JKQTBasePlotter *parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

    virtual ~JKQTPGraphDecoratedLineStyleMixin();

    /** \brief set the head decorator style */
    void setHeadDecoratorStyle(const JKQTPLineDecoratorStyle & __value);
    /** \brief get the head decorator style */
    JKQTPLineDecoratorStyle getHeadDecoratorStyle() const;
    /** \brief set the tail decorator style */
    void setTailDecoratorStyle(const JKQTPLineDecoratorStyle & __value);
    /** \brief get the tail decorator style */
    JKQTPLineDecoratorStyle getTailDecoratorStyle() const;

    /** \copydoc m_headDecoratorSizeFactor */
    void setHeadDecoratorSizeFactor(const double & __value);
    /** \copydoc m_headDecoratorSizeFactor */
    double getHeadDecoratorSizeFactor() const;
    /** \copydoc m_tailDecoratorSizeFactor */
    void setTailDecoratorSizeFactor(const double & __value);
    /** \copydoc m_tailDecoratorSizeFactor */
    double getTailDecoratorSizeFactor() const;

    /** \brief calculates the tail decorator size from the line width \a line_width, using m_tailDecoratorSizeFactor and a non-linear scaling function
     *
     *  \see JKQTPLineDecoratorStyleCalcDecoratorSize()
     */
    double calcTailDecoratorSize(double line_width) const;
    /** \brief calculates the tail decorator size from the line width \a line_width, using m_headDecoratorSizeFactor and a non-linear scaling function
     *
     *  \see JKQTPLineDecoratorStyleCalcDecoratorSize()
     */
    double calcHeadDecoratorSize(double line_width) const;



    Q_PROPERTY(JKQTPLineDecoratorStyle headDecoratorStyle MEMBER m_headDecoratorStyle READ getHeadDecoratorStyle WRITE setHeadDecoratorStyle)
    Q_PROPERTY(JKQTPLineDecoratorStyle tailDecoratorStyle MEMBER m_tailDecoratorStyle READ getTailDecoratorStyle WRITE setTailDecoratorStyle)
    Q_PROPERTY(double headDecoratorSizeFactor MEMBER m_headDecoratorSizeFactor READ getHeadDecoratorSizeFactor WRITE setHeadDecoratorSizeFactor)
    Q_PROPERTY(double tailDecoratorSizeFactor MEMBER m_tailDecoratorSizeFactor READ getTailDecoratorSizeFactor WRITE setTailDecoratorSizeFactor)
private:
    /** \brief head decorator style */
    JKQTPLineDecoratorStyle m_headDecoratorStyle;
    /** \brief tail decorator style */
    JKQTPLineDecoratorStyle m_tailDecoratorStyle;
    /** \brief head decorator size-factor, used to calculate the size of the arrow from the line width */
    double m_headDecoratorSizeFactor;
    /** \brief tail decorator size-factor, used to calculate the size of the arrow from the line width */
    double m_tailDecoratorSizeFactor;
};





/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph symbols style
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
      - symbol style
      - symbol size
      - symbol (outline) color
      - symbol fill color (not required for all symbols)
      - symbol (line) width
    .
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphSymbolStyleMixin {
        Q_GADGET
    public:
        /** \brief class constructor */
        JKQTPGraphSymbolStyleMixin();
        /** \brief initiaize the symbol style (from the parent plotter) */
        void initSymbolStyle(JKQTBasePlotter *parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

        virtual ~JKQTPGraphSymbolStyleMixin();

        /** \brief set the type of the graph symbol */
        void setSymbolType(JKQTPGraphSymbols __value);
        /** \brief get the type of the graph symbol */
        JKQTPGraphSymbols getSymbolType() const;

        /** \brief set the size (=diameter in pt) of the graph symbol (in pt) */
        void setSymbolSize(double __value);
        /** \brief get the size (=diameter in pt) of the graph symbol (in pt) */
        double getSymbolSize() const;

        /** \brief set the color of the graph symbols */
        void setSymbolColor(const QColor & __value);
        /** \brief set the color of the graph symbols */
        QColor getSymbolColor() const;

        /** \brief set the color of filling of the graph symbols */
        void setSymbolFillColor(const QColor & __value);
        /** \brief set the color of filling of the graph symbols */
        QColor getSymbolFillColor() const;

        /** \brief set the line width of the graph symbol outline (in pt) */
        void setSymbolLineWidth(double __value);
        /** \brief get the line width of the graph symbol outline (in pt) */
        double getSymbolLineWidth() const;



        Q_PROPERTY(JKQTPGraphSymbols symbolType MEMBER m_symbolType READ getSymbolType WRITE setSymbolType)
        Q_PROPERTY(QColor symbolColor MEMBER m_symbolColor READ getSymbolColor WRITE setSymbolColor)
        Q_PROPERTY(QColor symbolFillColor MEMBER m_symbolFillColor READ getSymbolFillColor WRITE setSymbolFillColor)
        Q_PROPERTY(double symbolSize MEMBER m_symbolSize READ getSymbolSize WRITE setSymbolSize)
        Q_PROPERTY(double symbolLineWidth MEMBER m_symbolLineWidth READ getSymbolLineWidth WRITE setSymbolLineWidth)
    private:
        /** \brief which symbol to use for the datapoints */
        JKQTPGraphSymbols m_symbolType;
        /** \brief size (diameter in pt) of the symbol for the data points, given in pt */
        double m_symbolSize;
        /** \brief (outline) color of the symbol  */
        QColor m_symbolColor;
        /** \brief color of the symbol filling */
        QColor m_symbolFillColor;
        /** \brief width (in pt) of the lines used to plot the symbol for the data points, given in pt */
        double m_symbolLineWidth;
    protected:
        /** \brief constructs a QPen from the line styling properties */
        QPen getSymbolPen(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
        /** \brief constructs a QPen from the line styling properties */
        QBrush getSymbolBrush(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
        /*! \brief plot a symbol at location x,y (in painter coordinates), using the current style

            \param parent parent JKQTBasePlotter of the graph that uses this mix-in (used e.g. for line-width transformation)
            \param painter the <a href="http://doc.qt.io/qt-5/qpainter.html">QPainter</a> to draw to
            \param x x-coordinate of the symbol center
            \param y y-coordinate of the symbol center
         */
        void plotStyledSymbol(JKQTBasePlotter* parent, JKQTPEnhancedPainter& painter, double x, double y) const;
        /*! \brief plot a symbol at location x,y (in painter coordinates), using the current style

            \param parent parent JKQTBasePlotter of the graph that uses this mix-in (used e.g. for line-width transformation)
            \param painter the <a href="http://doc.qt.io/qt-5/qpainter.html">QPainter</a> to draw to
            \param x x-coordinate of the symbol center
            \param y y-coordinate of the symbol center
            \param symbolSize size of the symbol
         */
        void plotStyledSymbol(JKQTBasePlotter* parent, JKQTPEnhancedPainter& painter, double x, double y, double symbolSize) const;
        /*! \brief plot a symbol at location x,y (in painter coordinates), using the current style

            \param parent parent JKQTBasePlotter of the graph that uses this mix-in (used e.g. for line-width transformation)
            \param painter the <a href="http://doc.qt.io/qt-5/qpainter.html">QPainter</a> to draw to
            \param x x-coordinate of the symbol center
            \param y y-coordinate of the symbol center
            \param type type of the symbol
         */
        void plotStyledSymbol(JKQTBasePlotter* parent, JKQTPEnhancedPainter& painter, double x, double y, JKQTPGraphSymbols type) const;
        /*! \brief plot a symbol at location x,y (in painter coordinates), using the current style

            \param parent parent JKQTBasePlotter of the graph that uses this mix-in (used e.g. for line-width transformation)
            \param painter the <a href="http://doc.qt.io/qt-5/qpainter.html">QPainter</a> to draw to
            \param x x-coordinate of the symbol center
            \param y y-coordinate of the symbol center
            \param color color of the symbol
            \param fillColor fill color of the symbol
         */
        void plotStyledSymbol(JKQTBasePlotter* parent, JKQTPEnhancedPainter& painter, double x, double y, QColor color, QColor fillColor) const;


};









/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph filling (NOT the symbol filling though!)
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
      - fill style
      - fill color
      - fill texture/gradient/matrix (if required by fill style)
    .
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphFillStyleMixin {
        Q_GADGET
    public:
        /** \brief class constructor */
        JKQTPGraphFillStyleMixin();

        /** \brief initiaize the fill style (from the parent plotter) */
        void initFillStyle(JKQTBasePlotter* parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

        virtual ~JKQTPGraphFillStyleMixin();

        /** \brief set the fill style of the graph */
        void setFillStyle(Qt::BrushStyle __value);
        /** \brief get the fill style of the graph */
        Qt::BrushStyle getFillStyle() const;

        /** \brief set the color of the graph filling */
        void setFillColor(const QColor & __value);
        /** \brief set the color of the graph filling */
        QColor getFillColor() const;

        /** \brief set the color of the graph filling and sets fill style to Qt::TexturePattern */
        void setFillTexture(const QPixmap & __value);
        /** \brief set the color of the graph filling and sets fill style to Qt::TexturePattern */
        void setFillTexture(const QImage & __value);
        /** \brief set the color of the graph filling */
        QPixmap getFillTexture() const;
        /** \brief set the color of the graph filling */
        QImage getFillTextureImage() const;

        /** \brief set the filling of the graph to a gradient and sets fill style to a gradient setting */
        void setFillGradient(const QGradient & __value);
        /** \brief get the gradient object of the graph filling */
        const QGradient *getFillGradient() const;

        /** \brief sets a fill brush (overwrites all internal properties!) */
        void setFillBrush(const QBrush& b);
        /** \brief sets a fill transformation */
        void setFillTransform(const QTransform& b);

        Q_PROPERTY(Qt::BrushStyle fillStyle MEMBER m_fillStyle READ getFillStyle WRITE setFillStyle)
        Q_PROPERTY(QColor fillColor MEMBER m_fillColor READ getFillColor WRITE setFillColor)
    private:
        /** \brief fill style of the graph */
        QBrush m_fillBrush;
        /** \brief last fill color of the graph  */
        QColor m_fillColor;
    protected:
        /** \brief constructs a QBrush from the graph fill styling properties */
        QBrush getFillBrush(JKQTPEnhancedPainter &painter, JKQTBasePlotter* parent) const;
};



/** \brief This Mix-In class provides setter/getter methods, storage and other facilities for the graph line and fill style
 *  \ingroup jkqtplotter_basegraphs_stylemixins
*/
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphLineAndFillStyleMixin: public JKQTPGraphFillStyleMixin, public JKQTPGraphLineStyleMixin {
    Q_GADGET
public:
    /** \brief class constructor */
    JKQTPGraphLineAndFillStyleMixin();

    /** \copydoc m_drawLine */
    void setDrawLine(bool __value);
    /** \copydoc m_drawLine */
    bool getDrawLine() const;
    /** \copydoc m_drawLine */
    bool doDrawLine() const;

    /** \copydoc m_fillCurve */
    void setFillCurve(bool __value);
    /** \copydoc m_fillCurve */
    bool getFillCurve() const;
    /** \copydoc m_fillCurve */
    bool doFillCurve() const;


    Q_PROPERTY(bool drawLine MEMBER m_drawLine READ getDrawLine WRITE setDrawLine)
    Q_PROPERTY(bool fillCurve MEMBER m_fillCurve READ getFillCurve WRITE setFillCurve)
private:
    /** \brief indicates whether to draw a line on the circumference of the described area (i.e. along the data points from \c xColumn and \c yColumn as well as \c xColumn and \c yColumn2 or not */
    bool m_drawLine;
    /** \brief indicates whether to fill the space between the curve and the x-axis */
    bool m_fillCurve;
};



/*! \brief This Mix-In class provides setter/getter methods, storage and other facilities for text in graphs
    \ingroup jkqtplotter_basegraphs_stylemixins

    supported properties:
      - font name
      - font size
      - text color
    .
 */
class JKQTPLOTTER_LIB_EXPORT JKQTPGraphTextStyleMixin {
        Q_GADGET
    public:
        /** \brief class constructor */
        JKQTPGraphTextStyleMixin(JKQTBasePlotter *parent);

        /** \brief initiaize the fill style (from the parent plotter) */
        void initTextStyle(JKQTBasePlotter* parent, int &parentPlotStyle, JKQTPPlotStyleType styletype=JKQTPPlotStyleType::Default);

        virtual ~JKQTPGraphTextStyleMixin();

        /** \brief set the base font size of text */
        void setTextFontSize(double __value);
        /** \brief get the base font size of text */
        double getTextFontSize() const;

        /** \brief set the base font name of text */
        void setTextFontName(const QString& __value);
        /** \brief get the base font name of text */
        QString getTextFontName() const;

        /** \brief set the color of the text */
        void setTextColor(const QColor & __value);
        /** \brief set the color of the text */
        QColor getTextColor() const;



        Q_PROPERTY(QColor textColor MEMBER m_textColor READ getTextColor WRITE setTextColor)
        Q_PROPERTY(double textFontSize MEMBER m_textFontSize READ getTextFontSize WRITE setTextFontSize)
        Q_PROPERTY(QString textFontName MEMBER m_textFontName READ getTextFontName WRITE setTextFontName)
    private:
        /** \brief color of the text */
        QColor m_textColor;

        /** \brief base font size of text */
        double m_textFontSize;
        /** \brief name of the font to be used for the text */
        QString m_textFontName;
    protected:
};





#endif // jkqtpgraphsbasestylingmixins_H

/****************************************************************************
** Meta object code from reading C++ file 'glwidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtopengl/glwidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#include <QtCore/QList>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'glwidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget_t {
    QByteArrayData data[19];
    char stringdata0[248];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget_t qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget = {
    {
QT_MOC_LITERAL(0, 0, 28), // "Avogadro::QtOpenGL::GLWidget"
QT_MOC_LITERAL(1, 29, 15), // "rendererInvalid"
QT_MOC_LITERAL(2, 45, 0), // ""
QT_MOC_LITERAL(3, 46, 11), // "updateScene"
QT_MOC_LITERAL(4, 58, 14), // "updateMolecule"
QT_MOC_LITERAL(5, 73, 10), // "clearScene"
QT_MOC_LITERAL(6, 84, 11), // "resetCamera"
QT_MOC_LITERAL(7, 96, 13), // "resetGeometry"
QT_MOC_LITERAL(8, 110, 8), // "setTools"
QT_MOC_LITERAL(9, 119, 25), // "QList<QtGui::ToolPlugin*>"
QT_MOC_LITERAL(10, 145, 8), // "toolList"
QT_MOC_LITERAL(11, 154, 7), // "addTool"
QT_MOC_LITERAL(12, 162, 18), // "QtGui::ToolPlugin*"
QT_MOC_LITERAL(13, 181, 4), // "tool"
QT_MOC_LITERAL(14, 186, 13), // "setActiveTool"
QT_MOC_LITERAL(15, 200, 4), // "name"
QT_MOC_LITERAL(16, 205, 14), // "setDefaultTool"
QT_MOC_LITERAL(17, 220, 13), // "requestUpdate"
QT_MOC_LITERAL(18, 234, 13) // "updateTimeout"

    },
    "Avogadro::QtOpenGL::GLWidget\0"
    "rendererInvalid\0\0updateScene\0"
    "updateMolecule\0clearScene\0resetCamera\0"
    "resetGeometry\0setTools\0QList<QtGui::ToolPlugin*>\0"
    "toolList\0addTool\0QtGui::ToolPlugin*\0"
    "tool\0setActiveTool\0name\0setDefaultTool\0"
    "requestUpdate\0updateTimeout"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtOpenGL__GLWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   84,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    0,   85,    2, 0x0a /* Public */,
       4,    0,   86,    2, 0x0a /* Public */,
       5,    0,   87,    2, 0x0a /* Public */,
       6,    0,   88,    2, 0x0a /* Public */,
       7,    0,   89,    2, 0x0a /* Public */,
       8,    1,   90,    2, 0x0a /* Public */,
      11,    1,   93,    2, 0x0a /* Public */,
      14,    1,   96,    2, 0x0a /* Public */,
      14,    1,   99,    2, 0x0a /* Public */,
      16,    1,  102,    2, 0x0a /* Public */,
      16,    1,  105,    2, 0x0a /* Public */,
      17,    0,  108,    2, 0x0a /* Public */,
      18,    0,  109,    2, 0x09 /* Protected */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void, 0x80000000 | 12,   13,
    QMetaType::Void, QMetaType::QString,   15,
    QMetaType::Void, 0x80000000 | 12,   13,
    QMetaType::Void, QMetaType::QString,   15,
    QMetaType::Void, 0x80000000 | 12,   13,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtOpenGL::GLWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<GLWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->rendererInvalid(); break;
        case 1: _t->updateScene(); break;
        case 2: _t->updateMolecule(); break;
        case 3: _t->clearScene(); break;
        case 4: _t->resetCamera(); break;
        case 5: _t->resetGeometry(); break;
        case 6: _t->setTools((*reinterpret_cast< const QList<QtGui::ToolPlugin*>(*)>(_a[1]))); break;
        case 7: _t->addTool((*reinterpret_cast< QtGui::ToolPlugin*(*)>(_a[1]))); break;
        case 8: _t->setActiveTool((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 9: _t->setActiveTool((*reinterpret_cast< QtGui::ToolPlugin*(*)>(_a[1]))); break;
        case 10: _t->setDefaultTool((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 11: _t->setDefaultTool((*reinterpret_cast< QtGui::ToolPlugin*(*)>(_a[1]))); break;
        case 12: _t->requestUpdate(); break;
        case 13: _t->updateTimeout(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (GLWidget::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&GLWidget::rendererInvalid)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtOpenGL::GLWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QOpenGLWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget.data,
    qt_meta_data_Avogadro__QtOpenGL__GLWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtOpenGL::GLWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtOpenGL::GLWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtOpenGL__GLWidget.stringdata0))
        return static_cast<void*>(this);
    return QOpenGLWidget::qt_metacast(_clname);
}

int Avogadro::QtOpenGL::GLWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QOpenGLWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 14;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtOpenGL::GLWidget::rendererInvalid()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

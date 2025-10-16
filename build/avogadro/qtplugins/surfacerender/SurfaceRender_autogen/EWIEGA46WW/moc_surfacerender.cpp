/****************************************************************************
** Meta object code from reading C++ file 'surfacerender.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/surfacerender/surfacerender.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'surfacerender.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender_t {
    QByteArrayData data[11];
    char stringdata0[115];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender_t qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender = {
    {
QT_MOC_LITERAL(0, 0, 34), // "Avogadro::QtPlugins::SurfaceR..."
QT_MOC_LITERAL(1, 35, 9), // "setColor1"
QT_MOC_LITERAL(2, 45, 0), // ""
QT_MOC_LITERAL(3, 46, 5), // "color"
QT_MOC_LITERAL(4, 52, 9), // "setColor2"
QT_MOC_LITERAL(5, 62, 10), // "setOpacity"
QT_MOC_LITERAL(6, 73, 7), // "opacity"
QT_MOC_LITERAL(7, 81, 8), // "setStyle"
QT_MOC_LITERAL(8, 90, 5), // "style"
QT_MOC_LITERAL(9, 96, 12), // "setLineWidth"
QT_MOC_LITERAL(10, 109, 5) // "width"

    },
    "Avogadro::QtPlugins::SurfaceRender\0"
    "setColor1\0\0color\0setColor2\0setOpacity\0"
    "opacity\0setStyle\0style\0setLineWidth\0"
    "width"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SurfaceRender[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   39,    2, 0x08 /* Private */,
       4,    1,   42,    2, 0x08 /* Private */,
       5,    1,   45,    2, 0x08 /* Private */,
       7,    1,   48,    2, 0x08 /* Private */,
       9,    1,   51,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::QColor,    3,
    QMetaType::Void, QMetaType::QColor,    3,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::Int,    8,
    QMetaType::Void, QMetaType::Double,   10,

       0        // eod
};

void Avogadro::QtPlugins::SurfaceRender::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SurfaceRender *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setColor1((*reinterpret_cast< const QColor(*)>(_a[1]))); break;
        case 1: _t->setColor2((*reinterpret_cast< const QColor(*)>(_a[1]))); break;
        case 2: _t->setOpacity((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->setStyle((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->setLineWidth((*reinterpret_cast< double(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SurfaceRender::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ScenePlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender.data,
    qt_meta_data_Avogadro__QtPlugins__SurfaceRender,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SurfaceRender::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SurfaceRender::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SurfaceRender.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ScenePlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SurfaceRender::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ScenePlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 5;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

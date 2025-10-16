/****************************************************************************
** Meta object code from reading C++ file 'cartoons.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/cartoons/cartoons.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'cartoons.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Cartoons_t {
    QByteArrayData data[10];
    char stringdata0[118];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Cartoons_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Cartoons_t qt_meta_stringdata_Avogadro__QtPlugins__Cartoons = {
    {
QT_MOC_LITERAL(0, 0, 29), // "Avogadro::QtPlugins::Cartoons"
QT_MOC_LITERAL(1, 30, 12), // "showBackbone"
QT_MOC_LITERAL(2, 43, 0), // ""
QT_MOC_LITERAL(3, 44, 4), // "show"
QT_MOC_LITERAL(4, 49, 9), // "showTrace"
QT_MOC_LITERAL(5, 59, 8), // "showTube"
QT_MOC_LITERAL(6, 68, 10), // "showRibbon"
QT_MOC_LITERAL(7, 79, 17), // "showSimpleCartoon"
QT_MOC_LITERAL(8, 97, 11), // "showCartoon"
QT_MOC_LITERAL(9, 109, 8) // "showRope"

    },
    "Avogadro::QtPlugins::Cartoons\0"
    "showBackbone\0\0show\0showTrace\0showTube\0"
    "showRibbon\0showSimpleCartoon\0showCartoon\0"
    "showRope"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Cartoons[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   49,    2, 0x0a /* Public */,
       4,    1,   52,    2, 0x0a /* Public */,
       5,    1,   55,    2, 0x0a /* Public */,
       6,    1,   58,    2, 0x0a /* Public */,
       7,    1,   61,    2, 0x0a /* Public */,
       8,    1,   64,    2, 0x0a /* Public */,
       9,    1,   67,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,

       0        // eod
};

void Avogadro::QtPlugins::Cartoons::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Cartoons *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->showBackbone((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 1: _t->showTrace((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 2: _t->showTube((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->showRibbon((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->showSimpleCartoon((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->showCartoon((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->showRope((*reinterpret_cast< bool(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Cartoons::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ScenePlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Cartoons.data,
    qt_meta_data_Avogadro__QtPlugins__Cartoons,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Cartoons::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Cartoons::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Cartoons.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ScenePlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Cartoons::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ScenePlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

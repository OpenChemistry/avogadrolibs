/****************************************************************************
** Meta object code from reading C++ file 'noncovalent.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/noncovalent/noncovalent.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'noncovalent.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent_t {
    QByteArrayData data[10];
    char stringdata0[133];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent_t qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent = {
    {
QT_MOC_LITERAL(0, 0, 32), // "Avogadro::QtPlugins::NonCovalent"
QT_MOC_LITERAL(1, 33, 17), // "setAngleTolerance"
QT_MOC_LITERAL(2, 51, 0), // ""
QT_MOC_LITERAL(3, 52, 14), // "angleTolerance"
QT_MOC_LITERAL(4, 67, 5), // "Index"
QT_MOC_LITERAL(5, 73, 5), // "index"
QT_MOC_LITERAL(6, 79, 18), // "setMaximumDistance"
QT_MOC_LITERAL(7, 98, 15), // "maximumDistance"
QT_MOC_LITERAL(8, 114, 12), // "setLineWidth"
QT_MOC_LITERAL(9, 127, 5) // "width"

    },
    "Avogadro::QtPlugins::NonCovalent\0"
    "setAngleTolerance\0\0angleTolerance\0"
    "Index\0index\0setMaximumDistance\0"
    "maximumDistance\0setLineWidth\0width"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__NonCovalent[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    2,   29,    2, 0x0a /* Public */,
       6,    2,   34,    2, 0x0a /* Public */,
       8,    2,   39,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void, QMetaType::Float, 0x80000000 | 4,    3,    5,
    QMetaType::Void, QMetaType::Float, 0x80000000 | 4,    7,    5,
    QMetaType::Void, QMetaType::Float, 0x80000000 | 4,    9,    5,

       0        // eod
};

void Avogadro::QtPlugins::NonCovalent::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<NonCovalent *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setAngleTolerance((*reinterpret_cast< float(*)>(_a[1])),(*reinterpret_cast< Index(*)>(_a[2]))); break;
        case 1: _t->setMaximumDistance((*reinterpret_cast< float(*)>(_a[1])),(*reinterpret_cast< Index(*)>(_a[2]))); break;
        case 2: _t->setLineWidth((*reinterpret_cast< float(*)>(_a[1])),(*reinterpret_cast< Index(*)>(_a[2]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::NonCovalent::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ScenePlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent.data,
    qt_meta_data_Avogadro__QtPlugins__NonCovalent,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::NonCovalent::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::NonCovalent::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__NonCovalent.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ScenePlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::NonCovalent::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ScenePlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 3;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

/****************************************************************************
** Meta object code from reading C++ file 'forcefield.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/forcefield/forcefield.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'forcefield.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Forcefield_t {
    QByteArrayData data[15];
    char stringdata0[207];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Forcefield_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Forcefield_t qt_meta_stringdata_Avogadro__QtPlugins__Forcefield = {
    {
QT_MOC_LITERAL(0, 0, 31), // "Avogadro::QtPlugins::Forcefield"
QT_MOC_LITERAL(1, 32, 14), // "refreshScripts"
QT_MOC_LITERAL(2, 47, 0), // ""
QT_MOC_LITERAL(3, 48, 15), // "registerScripts"
QT_MOC_LITERAL(4, 64, 17), // "unregisterScripts"
QT_MOC_LITERAL(5, 82, 10), // "showDialog"
QT_MOC_LITERAL(6, 93, 6), // "energy"
QT_MOC_LITERAL(7, 100, 6), // "forces"
QT_MOC_LITERAL(8, 107, 8), // "optimize"
QT_MOC_LITERAL(9, 116, 14), // "freezeSelected"
QT_MOC_LITERAL(10, 131, 16), // "unfreezeSelected"
QT_MOC_LITERAL(11, 148, 16), // "setupConstraints"
QT_MOC_LITERAL(12, 165, 12), // "fuseSelected"
QT_MOC_LITERAL(13, 178, 14), // "unfuseSelected"
QT_MOC_LITERAL(14, 193, 13) // "updateActions"

    },
    "Avogadro::QtPlugins::Forcefield\0"
    "refreshScripts\0\0registerScripts\0"
    "unregisterScripts\0showDialog\0energy\0"
    "forces\0optimize\0freezeSelected\0"
    "unfreezeSelected\0setupConstraints\0"
    "fuseSelected\0unfuseSelected\0updateActions"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Forcefield[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   79,    2, 0x0a /* Public */,
       3,    0,   80,    2, 0x0a /* Public */,
       4,    0,   81,    2, 0x0a /* Public */,
       5,    0,   82,    2, 0x0a /* Public */,
       6,    0,   83,    2, 0x08 /* Private */,
       7,    0,   84,    2, 0x08 /* Private */,
       8,    0,   85,    2, 0x08 /* Private */,
       9,    0,   86,    2, 0x08 /* Private */,
      10,    0,   87,    2, 0x08 /* Private */,
      11,    0,   88,    2, 0x08 /* Private */,
      12,    0,   89,    2, 0x08 /* Private */,
      13,    0,   90,    2, 0x08 /* Private */,
      14,    0,   91,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::Forcefield::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Forcefield *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->refreshScripts(); break;
        case 1: _t->registerScripts(); break;
        case 2: _t->unregisterScripts(); break;
        case 3: _t->showDialog(); break;
        case 4: _t->energy(); break;
        case 5: _t->forces(); break;
        case 6: _t->optimize(); break;
        case 7: _t->freezeSelected(); break;
        case 8: _t->unfreezeSelected(); break;
        case 9: _t->setupConstraints(); break;
        case 10: _t->fuseSelected(); break;
        case 11: _t->unfuseSelected(); break;
        case 12: _t->updateActions(); break;
        default: ;
        }
    }
    (void)_a;
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Forcefield::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Forcefield.data,
    qt_meta_data_Avogadro__QtPlugins__Forcefield,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Forcefield::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Forcefield::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Forcefield.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Forcefield::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 13;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

/****************************************************************************
** Meta object code from reading C++ file 'symmetry.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/symmetry/symmetry.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'symmetry.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Symmetry_t {
    QByteArrayData data[11];
    char stringdata0[149];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Symmetry_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Symmetry_t qt_meta_stringdata_Avogadro__QtPlugins__Symmetry = {
    {
QT_MOC_LITERAL(0, 0, 29), // "Avogadro::QtPlugins::Symmetry"
QT_MOC_LITERAL(1, 30, 11), // "setMolecule"
QT_MOC_LITERAL(2, 42, 0), // ""
QT_MOC_LITERAL(3, 43, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 60, 3), // "mol"
QT_MOC_LITERAL(5, 64, 15), // "moleculeChanged"
QT_MOC_LITERAL(6, 80, 7), // "changes"
QT_MOC_LITERAL(7, 88, 13), // "updateActions"
QT_MOC_LITERAL(8, 102, 12), // "viewSymmetry"
QT_MOC_LITERAL(9, 115, 14), // "detectSymmetry"
QT_MOC_LITERAL(10, 130, 18) // "symmetrizeMolecule"

    },
    "Avogadro::QtPlugins::Symmetry\0setMolecule\0"
    "\0QtGui::Molecule*\0mol\0moleculeChanged\0"
    "changes\0updateActions\0viewSymmetry\0"
    "detectSymmetry\0symmetrizeMolecule"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Symmetry[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x0a /* Public */,
       5,    1,   47,    2, 0x0a /* Public */,
       7,    0,   50,    2, 0x08 /* Private */,
       8,    0,   51,    2, 0x08 /* Private */,
       9,    0,   52,    2, 0x08 /* Private */,
      10,    0,   53,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, QMetaType::UInt,    6,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::Symmetry::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Symmetry *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->moleculeChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 2: _t->updateActions(); break;
        case 3: _t->viewSymmetry(); break;
        case 4: _t->detectSymmetry(); break;
        case 5: _t->symmetrizeMolecule(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Symmetry::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Symmetry.data,
    qt_meta_data_Avogadro__QtPlugins__Symmetry,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Symmetry::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Symmetry::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Symmetry.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Symmetry::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

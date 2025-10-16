/****************************************************************************
** Meta object code from reading C++ file 'crystal.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/crystal/crystal.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'crystal.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Crystal_t {
    QByteArrayData data[16];
    char stringdata0[228];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Crystal_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Crystal_t qt_meta_stringdata_Avogadro__QtPlugins__Crystal = {
    {
QT_MOC_LITERAL(0, 0, 28), // "Avogadro::QtPlugins::Crystal"
QT_MOC_LITERAL(1, 29, 11), // "setMolecule"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 59, 3), // "mol"
QT_MOC_LITERAL(5, 63, 15), // "moleculeChanged"
QT_MOC_LITERAL(6, 79, 7), // "changes"
QT_MOC_LITERAL(7, 87, 13), // "updateActions"
QT_MOC_LITERAL(8, 101, 22), // "importCrystalClipboard"
QT_MOC_LITERAL(9, 124, 12), // "editUnitCell"
QT_MOC_LITERAL(10, 137, 14), // "buildSupercell"
QT_MOC_LITERAL(11, 152, 12), // "niggliReduce"
QT_MOC_LITERAL(12, 165, 11), // "scaleVolume"
QT_MOC_LITERAL(13, 177, 19), // "standardOrientation"
QT_MOC_LITERAL(14, 197, 14), // "toggleUnitCell"
QT_MOC_LITERAL(15, 212, 15) // "wrapAtomsToCell"

    },
    "Avogadro::QtPlugins::Crystal\0setMolecule\0"
    "\0QtGui::Molecule*\0mol\0moleculeChanged\0"
    "changes\0updateActions\0importCrystalClipboard\0"
    "editUnitCell\0buildSupercell\0niggliReduce\0"
    "scaleVolume\0standardOrientation\0"
    "toggleUnitCell\0wrapAtomsToCell"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Crystal[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x0a /* Public */,
       5,    1,   72,    2, 0x0a /* Public */,
       7,    0,   75,    2, 0x08 /* Private */,
       8,    0,   76,    2, 0x08 /* Private */,
       9,    0,   77,    2, 0x08 /* Private */,
      10,    0,   78,    2, 0x08 /* Private */,
      11,    0,   79,    2, 0x08 /* Private */,
      12,    0,   80,    2, 0x08 /* Private */,
      13,    0,   81,    2, 0x08 /* Private */,
      14,    0,   82,    2, 0x08 /* Private */,
      15,    0,   83,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, QMetaType::UInt,    6,
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

void Avogadro::QtPlugins::Crystal::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Crystal *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->moleculeChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 2: _t->updateActions(); break;
        case 3: _t->importCrystalClipboard(); break;
        case 4: _t->editUnitCell(); break;
        case 5: _t->buildSupercell(); break;
        case 6: _t->niggliReduce(); break;
        case 7: _t->scaleVolume(); break;
        case 8: _t->standardOrientation(); break;
        case 9: _t->toggleUnitCell(); break;
        case 10: _t->wrapAtomsToCell(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Crystal::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Crystal.data,
    qt_meta_data_Avogadro__QtPlugins__Crystal,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Crystal::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Crystal::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Crystal.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Crystal::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 11;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

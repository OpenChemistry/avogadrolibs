/****************************************************************************
** Meta object code from reading C++ file 'spacegroup.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/spacegroup/spacegroup.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'spacegroup.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup_t {
    QByteArrayData data[15];
    char stringdata0[221];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup_t qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup = {
    {
QT_MOC_LITERAL(0, 0, 31), // "Avogadro::QtPlugins::SpaceGroup"
QT_MOC_LITERAL(1, 32, 11), // "setMolecule"
QT_MOC_LITERAL(2, 44, 0), // ""
QT_MOC_LITERAL(3, 45, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 62, 3), // "mol"
QT_MOC_LITERAL(5, 66, 15), // "moleculeChanged"
QT_MOC_LITERAL(6, 82, 7), // "changes"
QT_MOC_LITERAL(7, 90, 13), // "updateActions"
QT_MOC_LITERAL(8, 104, 18), // "perceiveSpaceGroup"
QT_MOC_LITERAL(9, 123, 17), // "reduceToPrimitive"
QT_MOC_LITERAL(10, 141, 19), // "conventionalizeCell"
QT_MOC_LITERAL(11, 161, 10), // "symmetrize"
QT_MOC_LITERAL(12, 172, 12), // "fillUnitCell"
QT_MOC_LITERAL(13, 185, 22), // "reduceToAsymmetricUnit"
QT_MOC_LITERAL(14, 208, 12) // "setTolerance"

    },
    "Avogadro::QtPlugins::SpaceGroup\0"
    "setMolecule\0\0QtGui::Molecule*\0mol\0"
    "moleculeChanged\0changes\0updateActions\0"
    "perceiveSpaceGroup\0reduceToPrimitive\0"
    "conventionalizeCell\0symmetrize\0"
    "fillUnitCell\0reduceToAsymmetricUnit\0"
    "setTolerance"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SpaceGroup[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   64,    2, 0x0a /* Public */,
       5,    1,   67,    2, 0x0a /* Public */,
       7,    0,   70,    2, 0x08 /* Private */,
       8,    0,   71,    2, 0x08 /* Private */,
       9,    0,   72,    2, 0x08 /* Private */,
      10,    0,   73,    2, 0x08 /* Private */,
      11,    0,   74,    2, 0x08 /* Private */,
      12,    0,   75,    2, 0x08 /* Private */,
      13,    0,   76,    2, 0x08 /* Private */,
      14,    0,   77,    2, 0x08 /* Private */,

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

       0        // eod
};

void Avogadro::QtPlugins::SpaceGroup::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SpaceGroup *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->moleculeChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 2: _t->updateActions(); break;
        case 3: _t->perceiveSpaceGroup(); break;
        case 4: _t->reduceToPrimitive(); break;
        case 5: _t->conventionalizeCell(); break;
        case 6: _t->symmetrize(); break;
        case 7: _t->fillUnitCell(); break;
        case 8: _t->reduceToAsymmetricUnit(); break;
        case 9: _t->setTolerance(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SpaceGroup::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup.data,
    qt_meta_data_Avogadro__QtPlugins__SpaceGroup,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SpaceGroup::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SpaceGroup::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SpaceGroup.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SpaceGroup::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 10)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 10;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

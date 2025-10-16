/****************************************************************************
** Meta object code from reading C++ file 'select.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/select/select.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'select.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Select_t {
    QByteArrayData data[23];
    char stringdata0[311];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Select_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Select_t qt_meta_stringdata_Avogadro__QtPlugins__Select = {
    {
QT_MOC_LITERAL(0, 0, 27), // "Avogadro::QtPlugins::Select"
QT_MOC_LITERAL(1, 28, 11), // "setMolecule"
QT_MOC_LITERAL(2, 40, 0), // ""
QT_MOC_LITERAL(3, 41, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 58, 3), // "mol"
QT_MOC_LITERAL(5, 62, 9), // "selectAll"
QT_MOC_LITERAL(6, 72, 10), // "selectNone"
QT_MOC_LITERAL(7, 83, 15), // "invertSelection"
QT_MOC_LITERAL(8, 99, 13), // "selectElement"
QT_MOC_LITERAL(9, 113, 15), // "selectAtomIndex"
QT_MOC_LITERAL(10, 129, 7), // "element"
QT_MOC_LITERAL(11, 137, 13), // "selectResidue"
QT_MOC_LITERAL(12, 151, 19), // "selectBackboneAtoms"
QT_MOC_LITERAL(13, 171, 20), // "selectSidechainAtoms"
QT_MOC_LITERAL(14, 192, 11), // "selectWater"
QT_MOC_LITERAL(15, 204, 13), // "isWaterOxygen"
QT_MOC_LITERAL(16, 218, 5), // "Index"
QT_MOC_LITERAL(17, 224, 1), // "i"
QT_MOC_LITERAL(18, 226, 16), // "enlargeSelection"
QT_MOC_LITERAL(19, 243, 15), // "shrinkSelection"
QT_MOC_LITERAL(20, 259, 18), // "getSelectionCenter"
QT_MOC_LITERAL(21, 278, 7), // "Vector3"
QT_MOC_LITERAL(22, 286, 24) // "createLayerFromSelection"

    },
    "Avogadro::QtPlugins::Select\0setMolecule\0"
    "\0QtGui::Molecule*\0mol\0selectAll\0"
    "selectNone\0invertSelection\0selectElement\0"
    "selectAtomIndex\0element\0selectResidue\0"
    "selectBackboneAtoms\0selectSidechainAtoms\0"
    "selectWater\0isWaterOxygen\0Index\0i\0"
    "enlargeSelection\0shrinkSelection\0"
    "getSelectionCenter\0Vector3\0"
    "createLayerFromSelection"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Select[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   94,    2, 0x0a /* Public */,
       5,    0,   97,    2, 0x08 /* Private */,
       6,    0,   98,    2, 0x08 /* Private */,
       7,    0,   99,    2, 0x08 /* Private */,
       8,    0,  100,    2, 0x08 /* Private */,
       9,    0,  101,    2, 0x08 /* Private */,
       8,    1,  102,    2, 0x08 /* Private */,
      11,    0,  105,    2, 0x08 /* Private */,
      12,    0,  106,    2, 0x08 /* Private */,
      13,    0,  107,    2, 0x08 /* Private */,
      14,    0,  108,    2, 0x08 /* Private */,
      15,    1,  109,    2, 0x08 /* Private */,
      18,    0,  112,    2, 0x08 /* Private */,
      19,    0,  113,    2, 0x08 /* Private */,
      20,    0,  114,    2, 0x08 /* Private */,
      22,    0,  115,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   10,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Bool, 0x80000000 | 16,   17,
    QMetaType::Void,
    QMetaType::Void,
    0x80000000 | 21,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::Select::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Select *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->selectAll(); break;
        case 2: _t->selectNone(); break;
        case 3: _t->invertSelection(); break;
        case 4: _t->selectElement(); break;
        case 5: _t->selectAtomIndex(); break;
        case 6: _t->selectElement((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->selectResidue(); break;
        case 8: _t->selectBackboneAtoms(); break;
        case 9: _t->selectSidechainAtoms(); break;
        case 10: _t->selectWater(); break;
        case 11: { bool _r = _t->isWaterOxygen((*reinterpret_cast< Index(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 12: _t->enlargeSelection(); break;
        case 13: _t->shrinkSelection(); break;
        case 14: { Vector3 _r = _t->getSelectionCenter();
            if (_a[0]) *reinterpret_cast< Vector3*>(_a[0]) = std::move(_r); }  break;
        case 15: _t->createLayerFromSelection(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Select::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Select.data,
    qt_meta_data_Avogadro__QtPlugins__Select,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Select::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Select::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Select.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Select::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 16)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 16;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 16)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 16;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

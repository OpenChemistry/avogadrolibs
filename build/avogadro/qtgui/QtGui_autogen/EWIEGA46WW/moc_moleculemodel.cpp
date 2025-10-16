/****************************************************************************
** Meta object code from reading C++ file 'moleculemodel.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/moleculemodel.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'moleculemodel.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__MoleculeModel_t {
    QByteArrayData data[12];
    char stringdata0[160];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__MoleculeModel_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__MoleculeModel_t qt_meta_stringdata_Avogadro__QtGui__MoleculeModel = {
    {
QT_MOC_LITERAL(0, 0, 30), // "Avogadro::QtGui::MoleculeModel"
QT_MOC_LITERAL(1, 31, 20), // "moleculeStateChanged"
QT_MOC_LITERAL(2, 52, 0), // ""
QT_MOC_LITERAL(3, 53, 26), // "Avogadro::QtGui::Molecule*"
QT_MOC_LITERAL(4, 80, 17), // "setActiveMolecule"
QT_MOC_LITERAL(5, 98, 6), // "active"
QT_MOC_LITERAL(6, 105, 7), // "addItem"
QT_MOC_LITERAL(7, 113, 4), // "item"
QT_MOC_LITERAL(8, 118, 10), // "removeItem"
QT_MOC_LITERAL(9, 129, 11), // "itemChanged"
QT_MOC_LITERAL(10, 141, 9), // "loadIcons"
QT_MOC_LITERAL(11, 151, 8) // "darkMode"

    },
    "Avogadro::QtGui::MoleculeModel\0"
    "moleculeStateChanged\0\0Avogadro::QtGui::Molecule*\0"
    "setActiveMolecule\0active\0addItem\0item\0"
    "removeItem\0itemChanged\0loadIcons\0"
    "darkMode"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__MoleculeModel[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    1,   47,    2, 0x0a /* Public */,
       6,    1,   50,    2, 0x0a /* Public */,
       8,    1,   53,    2, 0x0a /* Public */,
       9,    0,   56,    2, 0x0a /* Public */,
      10,    1,   57,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    2,

 // slots: parameters
    QMetaType::Void, QMetaType::QObjectStar,    5,
    QMetaType::Void, 0x80000000 | 3,    7,
    QMetaType::Void, 0x80000000 | 3,    7,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   11,

       0        // eod
};

void Avogadro::QtGui::MoleculeModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MoleculeModel *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->moleculeStateChanged((*reinterpret_cast< Avogadro::QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->setActiveMolecule((*reinterpret_cast< QObject*(*)>(_a[1]))); break;
        case 2: _t->addItem((*reinterpret_cast< Avogadro::QtGui::Molecule*(*)>(_a[1]))); break;
        case 3: _t->removeItem((*reinterpret_cast< Avogadro::QtGui::Molecule*(*)>(_a[1]))); break;
        case 4: _t->itemChanged(); break;
        case 5: _t->loadIcons((*reinterpret_cast< bool(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (MoleculeModel::*)(Avogadro::QtGui::Molecule * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&MoleculeModel::moleculeStateChanged)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::MoleculeModel::staticMetaObject = { {
    QMetaObject::SuperData::link<QAbstractItemModel::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__MoleculeModel.data,
    qt_meta_data_Avogadro__QtGui__MoleculeModel,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::MoleculeModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::MoleculeModel::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__MoleculeModel.stringdata0))
        return static_cast<void*>(this);
    return QAbstractItemModel::qt_metacast(_clname);
}

int Avogadro::QtGui::MoleculeModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QAbstractItemModel::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void Avogadro::QtGui::MoleculeModel::moleculeStateChanged(Avogadro::QtGui::Molecule * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

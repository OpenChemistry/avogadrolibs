/****************************************************************************
** Meta object code from reading C++ file 'molecule.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/molecule.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'molecule.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__Molecule_t {
    QByteArrayData data[7];
    char stringdata0[72];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__Molecule_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__Molecule_t qt_meta_stringdata_Avogadro__QtGui__Molecule = {
    {
QT_MOC_LITERAL(0, 0, 25), // "Avogadro::QtGui::Molecule"
QT_MOC_LITERAL(1, 26, 7), // "changed"
QT_MOC_LITERAL(2, 34, 0), // ""
QT_MOC_LITERAL(3, 35, 6), // "change"
QT_MOC_LITERAL(4, 42, 6), // "update"
QT_MOC_LITERAL(5, 49, 11), // "emitChanged"
QT_MOC_LITERAL(6, 61, 10) // "emitUpdate"

    },
    "Avogadro::QtGui::Molecule\0changed\0\0"
    "change\0update\0emitChanged\0emitUpdate"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__Molecule[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   34,    2, 0x06 /* Public */,
       4,    0,   37,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   38,    2, 0x0a /* Public */,
       6,    0,   41,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::UInt,    3,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::UInt,    3,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtGui::Molecule::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Molecule *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->changed((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 1: _t->update(); break;
        case 2: _t->emitChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 3: _t->emitUpdate(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Molecule::*)(unsigned int ) const;
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Molecule::changed)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Molecule::*)() const;
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Molecule::update)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::Molecule::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__Molecule.data,
    qt_meta_data_Avogadro__QtGui__Molecule,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::Molecule::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::Molecule::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__Molecule.stringdata0))
        return static_cast<void*>(this);
    if (!strcmp(_clname, "Core::Molecule"))
        return static_cast< Core::Molecule*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::QtGui::Molecule::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 4)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 4;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtGui::Molecule::changed(unsigned int _t1)const
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(const_cast< Avogadro::QtGui::Molecule *>(this), &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtGui::Molecule::update()const
{
    QMetaObject::activate(const_cast< Avogadro::QtGui::Molecule *>(this), &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

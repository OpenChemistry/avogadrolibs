/****************************************************************************
** Meta object code from reading C++ file 'conformersearchdialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/openbabel/conformersearchdialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'conformersearchdialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__ConformerSearchDialog_t {
    QByteArrayData data[13];
    char stringdata0[165];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__ConformerSearchDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__ConformerSearchDialog_t qt_meta_stringdata_Avogadro__ConformerSearchDialog = {
    {
QT_MOC_LITERAL(0, 0, 31), // "Avogadro::ConformerSearchDialog"
QT_MOC_LITERAL(1, 32, 8), // "accepted"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 6), // "accept"
QT_MOC_LITERAL(4, 49, 6), // "reject"
QT_MOC_LITERAL(5, 56, 17), // "systematicToggled"
QT_MOC_LITERAL(6, 74, 7), // "checked"
QT_MOC_LITERAL(7, 82, 13), // "randomToggled"
QT_MOC_LITERAL(8, 96, 15), // "weightedToggled"
QT_MOC_LITERAL(9, 112, 14), // "geneticToggled"
QT_MOC_LITERAL(10, 127, 13), // "buttonClicked"
QT_MOC_LITERAL(11, 141, 16), // "QAbstractButton*"
QT_MOC_LITERAL(12, 158, 6) // "button"

    },
    "Avogadro::ConformerSearchDialog\0"
    "accepted\0\0accept\0reject\0systematicToggled\0"
    "checked\0randomToggled\0weightedToggled\0"
    "geneticToggled\0buttonClicked\0"
    "QAbstractButton*\0button"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__ConformerSearchDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   54,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    0,   55,    2, 0x0a /* Public */,
       4,    0,   56,    2, 0x0a /* Public */,
       5,    1,   57,    2, 0x0a /* Public */,
       7,    1,   60,    2, 0x0a /* Public */,
       8,    1,   63,    2, 0x0a /* Public */,
       9,    1,   66,    2, 0x0a /* Public */,
      10,    1,   69,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,    6,
    QMetaType::Void, QMetaType::Bool,    6,
    QMetaType::Void, QMetaType::Bool,    6,
    QMetaType::Void, QMetaType::Bool,    6,
    QMetaType::Void, 0x80000000 | 11,   12,

       0        // eod
};

void Avogadro::ConformerSearchDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ConformerSearchDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->accepted(); break;
        case 1: _t->accept(); break;
        case 2: _t->reject(); break;
        case 3: _t->systematicToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->randomToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->weightedToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->geneticToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->buttonClicked((*reinterpret_cast< QAbstractButton*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ConformerSearchDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ConformerSearchDialog::accepted)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::ConformerSearchDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__ConformerSearchDialog.data,
    qt_meta_data_Avogadro__ConformerSearchDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::ConformerSearchDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::ConformerSearchDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__ConformerSearchDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int Avogadro::ConformerSearchDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 8;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::ConformerSearchDialog::accepted()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

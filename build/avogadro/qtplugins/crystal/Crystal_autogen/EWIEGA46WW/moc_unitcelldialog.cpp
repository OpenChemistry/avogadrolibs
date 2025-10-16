/****************************************************************************
** Meta object code from reading C++ file 'unitcelldialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/crystal/unitcelldialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'unitcelldialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog_t {
    QByteArrayData data[9];
    char stringdata0[131];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog_t qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog = {
    {
QT_MOC_LITERAL(0, 0, 35), // "Avogadro::QtPlugins::UnitCell..."
QT_MOC_LITERAL(1, 36, 15), // "moleculeChanged"
QT_MOC_LITERAL(2, 52, 0), // ""
QT_MOC_LITERAL(3, 53, 7), // "changes"
QT_MOC_LITERAL(4, 61, 16), // "parametersEdited"
QT_MOC_LITERAL(5, 78, 16), // "cellMatrixEdited"
QT_MOC_LITERAL(6, 95, 22), // "fractionalMatrixEdited"
QT_MOC_LITERAL(7, 118, 5), // "apply"
QT_MOC_LITERAL(8, 124, 6) // "revert"

    },
    "Avogadro::QtPlugins::UnitCellDialog\0"
    "moleculeChanged\0\0changes\0parametersEdited\0"
    "cellMatrixEdited\0fractionalMatrixEdited\0"
    "apply\0revert"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__UnitCellDialog[] = {

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
       4,    0,   47,    2, 0x0a /* Public */,
       5,    0,   48,    2, 0x0a /* Public */,
       6,    0,   49,    2, 0x0a /* Public */,
       7,    0,   50,    2, 0x0a /* Public */,
       8,    0,   51,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void, QMetaType::UInt,    3,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::UnitCellDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<UnitCellDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->moleculeChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 1: _t->parametersEdited(); break;
        case 2: _t->cellMatrixEdited(); break;
        case 3: _t->fractionalMatrixEdited(); break;
        case 4: _t->apply(); break;
        case 5: _t->revert(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::UnitCellDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog.data,
    qt_meta_data_Avogadro__QtPlugins__UnitCellDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::UnitCellDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::UnitCellDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__UnitCellDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int Avogadro::QtPlugins::UnitCellDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
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

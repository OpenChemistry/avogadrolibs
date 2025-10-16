/****************************************************************************
** Meta object code from reading C++ file 'constraintsdialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/constraints/constraintsdialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'constraintsdialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog_t {
    QByteArrayData data[13];
    char stringdata0[192];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog_t qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog = {
    {
QT_MOC_LITERAL(0, 0, 38), // "Avogadro::QtPlugins::Constrai..."
QT_MOC_LITERAL(1, 39, 17), // "acceptConstraints"
QT_MOC_LITERAL(2, 57, 0), // ""
QT_MOC_LITERAL(3, 58, 13), // "addConstraint"
QT_MOC_LITERAL(4, 72, 16), // "deleteConstraint"
QT_MOC_LITERAL(5, 89, 20), // "deleteAllConstraints"
QT_MOC_LITERAL(6, 110, 17), // "highlightSelected"
QT_MOC_LITERAL(7, 128, 11), // "QModelIndex"
QT_MOC_LITERAL(8, 140, 8), // "newIndex"
QT_MOC_LITERAL(9, 149, 8), // "oldIndex"
QT_MOC_LITERAL(10, 158, 10), // "changeType"
QT_MOC_LITERAL(11, 169, 4), // "type"
QT_MOC_LITERAL(12, 174, 17) // "updateConstraints"

    },
    "Avogadro::QtPlugins::ConstraintsDialog\0"
    "acceptConstraints\0\0addConstraint\0"
    "deleteConstraint\0deleteAllConstraints\0"
    "highlightSelected\0QModelIndex\0newIndex\0"
    "oldIndex\0changeType\0type\0updateConstraints"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__ConstraintsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   49,    2, 0x0a /* Public */,
       3,    0,   50,    2, 0x0a /* Public */,
       4,    0,   51,    2, 0x0a /* Public */,
       5,    0,   52,    2, 0x0a /* Public */,
       6,    2,   53,    2, 0x0a /* Public */,
      10,    1,   58,    2, 0x0a /* Public */,
      12,    0,   61,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 7, 0x80000000 | 7,    8,    9,
    QMetaType::Void, QMetaType::Int,   11,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::ConstraintsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ConstraintsDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->acceptConstraints(); break;
        case 1: _t->addConstraint(); break;
        case 2: _t->deleteConstraint(); break;
        case 3: _t->deleteAllConstraints(); break;
        case 4: _t->highlightSelected((*reinterpret_cast< const QModelIndex(*)>(_a[1])),(*reinterpret_cast< const QModelIndex(*)>(_a[2]))); break;
        case 5: _t->changeType((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->updateConstraints(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::ConstraintsDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog.data,
    qt_meta_data_Avogadro__QtPlugins__ConstraintsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::ConstraintsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::ConstraintsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__ConstraintsDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int Avogadro::QtPlugins::ConstraintsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

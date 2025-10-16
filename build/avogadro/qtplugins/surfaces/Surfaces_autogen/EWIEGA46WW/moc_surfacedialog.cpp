/****************************************************************************
** Meta object code from reading C++ file 'surfacedialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/surfaces/surfacedialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'surfacedialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog_t {
    QByteArrayData data[12];
    char stringdata0[197];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog_t qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog = {
    {
QT_MOC_LITERAL(0, 0, 34), // "Avogadro::QtPlugins::SurfaceD..."
QT_MOC_LITERAL(1, 35, 11), // "stepChanged"
QT_MOC_LITERAL(2, 47, 0), // ""
QT_MOC_LITERAL(3, 48, 1), // "n"
QT_MOC_LITERAL(4, 50, 22), // "calculateClickedSignal"
QT_MOC_LITERAL(5, 73, 13), // "recordClicked"
QT_MOC_LITERAL(6, 87, 19), // "surfaceComboChanged"
QT_MOC_LITERAL(7, 107, 20), // "propertyComboChanged"
QT_MOC_LITERAL(8, 128, 22), // "resolutionComboChanged"
QT_MOC_LITERAL(9, 151, 21), // "smoothingComboChanged"
QT_MOC_LITERAL(10, 173, 16), // "calculateClicked"
QT_MOC_LITERAL(11, 190, 6) // "record"

    },
    "Avogadro::QtPlugins::SurfaceDialog\0"
    "stepChanged\0\0n\0calculateClickedSignal\0"
    "recordClicked\0surfaceComboChanged\0"
    "propertyComboChanged\0resolutionComboChanged\0"
    "smoothingComboChanged\0calculateClicked\0"
    "record"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SurfaceDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   59,    2, 0x06 /* Public */,
       4,    0,   62,    2, 0x06 /* Public */,
       5,    0,   63,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       6,    1,   64,    2, 0x09 /* Protected */,
       7,    1,   67,    2, 0x09 /* Protected */,
       8,    1,   70,    2, 0x09 /* Protected */,
       9,    1,   73,    2, 0x09 /* Protected */,
      10,    0,   76,    2, 0x09 /* Protected */,
      11,    0,   77,    2, 0x09 /* Protected */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::SurfaceDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SurfaceDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->stepChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->calculateClickedSignal(); break;
        case 2: _t->recordClicked(); break;
        case 3: _t->surfaceComboChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->propertyComboChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->resolutionComboChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->smoothingComboChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->calculateClicked(); break;
        case 8: _t->record(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (SurfaceDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SurfaceDialog::stepChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (SurfaceDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SurfaceDialog::calculateClickedSignal)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (SurfaceDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SurfaceDialog::recordClicked)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SurfaceDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog.data,
    qt_meta_data_Avogadro__QtPlugins__SurfaceDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SurfaceDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SurfaceDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SurfaceDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SurfaceDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 9;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtPlugins::SurfaceDialog::stepChanged(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtPlugins::SurfaceDialog::calculateClickedSignal()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void Avogadro::QtPlugins::SurfaceDialog::recordClicked()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

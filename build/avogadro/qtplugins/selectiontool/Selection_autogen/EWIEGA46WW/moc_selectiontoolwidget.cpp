/****************************************************************************
** Meta object code from reading C++ file 'selectiontoolwidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/selectiontool/selectiontoolwidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'selectiontoolwidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget_t {
    QByteArrayData data[8];
    char stringdata0[106];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget_t qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget = {
    {
QT_MOC_LITERAL(0, 0, 40), // "Avogadro::QtPlugins::Selectio..."
QT_MOC_LITERAL(1, 41, 12), // "colorApplied"
QT_MOC_LITERAL(2, 54, 0), // ""
QT_MOC_LITERAL(3, 55, 9), // "Vector3ub"
QT_MOC_LITERAL(4, 65, 5), // "color"
QT_MOC_LITERAL(5, 71, 11), // "changeLayer"
QT_MOC_LITERAL(6, 83, 5), // "layer"
QT_MOC_LITERAL(7, 89, 16) // "userClickedColor"

    },
    "Avogadro::QtPlugins::SelectionToolWidget\0"
    "colorApplied\0\0Vector3ub\0color\0changeLayer\0"
    "layer\0userClickedColor"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SelectionToolWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   29,    2, 0x06 /* Public */,
       5,    1,   32,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       7,    0,   35,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, QMetaType::Int,    6,

 // slots: parameters
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::SelectionToolWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SelectionToolWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->colorApplied((*reinterpret_cast< Vector3ub(*)>(_a[1]))); break;
        case 1: _t->changeLayer((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->userClickedColor(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (SelectionToolWidget::*)(Vector3ub );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SelectionToolWidget::colorApplied)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (SelectionToolWidget::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SelectionToolWidget::changeLayer)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SelectionToolWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget.data,
    qt_meta_data_Avogadro__QtPlugins__SelectionToolWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SelectionToolWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SelectionToolWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SelectionToolWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SelectionToolWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtPlugins::SelectionToolWidget::colorApplied(Vector3ub _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtPlugins::SelectionToolWidget::changeLayer(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

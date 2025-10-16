/****************************************************************************
** Meta object code from reading C++ file 'selectiontool.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/selectiontool/selectiontool.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'selectiontool.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool_t {
    QByteArrayData data[7];
    char stringdata0[80];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool_t qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool = {
    {
QT_MOC_LITERAL(0, 0, 34), // "Avogadro::QtPlugins::Selectio..."
QT_MOC_LITERAL(1, 35, 10), // "applyColor"
QT_MOC_LITERAL(2, 46, 0), // ""
QT_MOC_LITERAL(3, 47, 9), // "Vector3ub"
QT_MOC_LITERAL(4, 57, 5), // "color"
QT_MOC_LITERAL(5, 63, 10), // "applyLayer"
QT_MOC_LITERAL(6, 74, 5) // "layer"

    },
    "Avogadro::QtPlugins::SelectionTool\0"
    "applyColor\0\0Vector3ub\0color\0applyLayer\0"
    "layer"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SelectionTool[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   24,    2, 0x08 /* Private */,
       5,    1,   27,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, QMetaType::Int,    6,

       0        // eod
};

void Avogadro::QtPlugins::SelectionTool::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SelectionTool *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->applyColor((*reinterpret_cast< Vector3ub(*)>(_a[1]))); break;
        case 1: _t->applyLayer((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SelectionTool::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ToolPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool.data,
    qt_meta_data_Avogadro__QtPlugins__SelectionTool,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SelectionTool::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SelectionTool::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SelectionTool.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ToolPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SelectionTool::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ToolPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 2;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

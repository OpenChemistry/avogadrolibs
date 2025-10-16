/****************************************************************************
** Meta object code from reading C++ file 'editortoolwidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/editor/editortoolwidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'editortoolwidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget_t {
    QByteArrayData data[9];
    char stringdata0[141];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget_t qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget = {
    {
QT_MOC_LITERAL(0, 0, 37), // "Avogadro::QtPlugins::EditorTo..."
QT_MOC_LITERAL(1, 38, 14), // "elementChanged"
QT_MOC_LITERAL(2, 53, 0), // ""
QT_MOC_LITERAL(3, 54, 5), // "index"
QT_MOC_LITERAL(4, 60, 18), // "updateElementCombo"
QT_MOC_LITERAL(5, 79, 14), // "addUserElement"
QT_MOC_LITERAL(6, 94, 7), // "element"
QT_MOC_LITERAL(7, 102, 24), // "elementSelectedFromTable"
QT_MOC_LITERAL(8, 127, 13) // "selectElement"

    },
    "Avogadro::QtPlugins::EditorToolWidget\0"
    "elementChanged\0\0index\0updateElementCombo\0"
    "addUserElement\0element\0elementSelectedFromTable\0"
    "selectElement"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__EditorToolWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   39,    2, 0x08 /* Private */,
       4,    0,   42,    2, 0x08 /* Private */,
       5,    1,   43,    2, 0x08 /* Private */,
       7,    1,   46,    2, 0x08 /* Private */,
       8,    1,   49,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void,
    QMetaType::Void, QMetaType::UChar,    6,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::UChar,    6,

       0        // eod
};

void Avogadro::QtPlugins::EditorToolWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<EditorToolWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->elementChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->updateElementCombo(); break;
        case 2: _t->addUserElement((*reinterpret_cast< unsigned char(*)>(_a[1]))); break;
        case 3: _t->elementSelectedFromTable((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->selectElement((*reinterpret_cast< unsigned char(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::EditorToolWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget.data,
    qt_meta_data_Avogadro__QtPlugins__EditorToolWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::EditorToolWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::EditorToolWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__EditorToolWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Avogadro::QtPlugins::EditorToolWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 5;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

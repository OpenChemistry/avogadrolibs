/****************************************************************************
** Meta object code from reading C++ file 'templatetoolwidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/templatetool/templatetoolwidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'templatetoolwidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget_t {
    QByteArrayData data[16];
    char stringdata0[237];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget_t qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget = {
    {
QT_MOC_LITERAL(0, 0, 39), // "Avogadro::QtPlugins::Template..."
QT_MOC_LITERAL(1, 40, 14), // "elementChanged"
QT_MOC_LITERAL(2, 55, 0), // ""
QT_MOC_LITERAL(3, 56, 5), // "index"
QT_MOC_LITERAL(4, 62, 18), // "updateElementCombo"
QT_MOC_LITERAL(5, 81, 14), // "addUserElement"
QT_MOC_LITERAL(6, 96, 7), // "element"
QT_MOC_LITERAL(7, 104, 24), // "elementSelectedFromTable"
QT_MOC_LITERAL(8, 129, 13), // "selectElement"
QT_MOC_LITERAL(9, 143, 19), // "coordinationChanged"
QT_MOC_LITERAL(10, 163, 11), // "typeChanged"
QT_MOC_LITERAL(11, 175, 13), // "ligandChanged"
QT_MOC_LITERAL(12, 189, 12), // "groupChanged"
QT_MOC_LITERAL(13, 202, 17), // "otherLigandInsert"
QT_MOC_LITERAL(14, 220, 8), // "fileName"
QT_MOC_LITERAL(15, 229, 7) // "crystal"

    },
    "Avogadro::QtPlugins::TemplateToolWidget\0"
    "elementChanged\0\0index\0updateElementCombo\0"
    "addUserElement\0element\0elementSelectedFromTable\0"
    "selectElement\0coordinationChanged\0"
    "typeChanged\0ligandChanged\0groupChanged\0"
    "otherLigandInsert\0fileName\0crystal"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__TemplateToolWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   64,    2, 0x08 /* Private */,
       4,    0,   67,    2, 0x08 /* Private */,
       5,    1,   68,    2, 0x08 /* Private */,
       7,    1,   71,    2, 0x08 /* Private */,
       8,    1,   74,    2, 0x08 /* Private */,
       9,    1,   77,    2, 0x08 /* Private */,
      10,    1,   80,    2, 0x08 /* Private */,
      11,    1,   83,    2, 0x08 /* Private */,
      12,    1,   86,    2, 0x08 /* Private */,
      13,    2,   89,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void,
    QMetaType::Void, QMetaType::UChar,    6,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::UChar,    6,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,   14,   15,

       0        // eod
};

void Avogadro::QtPlugins::TemplateToolWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<TemplateToolWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->elementChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->updateElementCombo(); break;
        case 2: _t->addUserElement((*reinterpret_cast< unsigned char(*)>(_a[1]))); break;
        case 3: _t->elementSelectedFromTable((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->selectElement((*reinterpret_cast< unsigned char(*)>(_a[1]))); break;
        case 5: _t->coordinationChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 6: _t->typeChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->ligandChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 8: _t->groupChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 9: _t->otherLigandInsert((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::TemplateToolWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget.data,
    qt_meta_data_Avogadro__QtPlugins__TemplateToolWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::TemplateToolWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::TemplateToolWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__TemplateToolWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Avogadro::QtPlugins::TemplateToolWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 10)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 10;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

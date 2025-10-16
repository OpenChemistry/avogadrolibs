/****************************************************************************
** Meta object code from reading C++ file 'interfacewidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/interfacewidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'interfacewidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget_t {
    QByteArrayData data[8];
    char stringdata0[96];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget_t qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget = {
    {
QT_MOC_LITERAL(0, 0, 32), // "Avogadro::QtGui::InterfaceWidget"
QT_MOC_LITERAL(1, 33, 15), // "defaultsClicked"
QT_MOC_LITERAL(2, 49, 0), // ""
QT_MOC_LITERAL(3, 50, 14), // "setWarningText"
QT_MOC_LITERAL(4, 65, 4), // "warn"
QT_MOC_LITERAL(5, 70, 11), // "warningText"
QT_MOC_LITERAL(6, 82, 9), // "showError"
QT_MOC_LITERAL(7, 92, 3) // "err"

    },
    "Avogadro::QtGui::InterfaceWidget\0"
    "defaultsClicked\0\0setWarningText\0warn\0"
    "warningText\0showError\0err"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__InterfaceWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   34,    2, 0x08 /* Private */,
       3,    1,   35,    2, 0x08 /* Private */,
       5,    0,   38,    2, 0x08 /* Private */,
       6,    1,   39,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    4,
    QMetaType::QString,
    QMetaType::Void, QMetaType::QString,    7,

       0        // eod
};

void Avogadro::QtGui::InterfaceWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<InterfaceWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->defaultsClicked(); break;
        case 1: _t->setWarningText((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: { QString _r = _t->warningText();
            if (_a[0]) *reinterpret_cast< QString*>(_a[0]) = std::move(_r); }  break;
        case 3: _t->showError((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::InterfaceWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<JsonWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget.data,
    qt_meta_data_Avogadro__QtGui__InterfaceWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::InterfaceWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::InterfaceWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__InterfaceWidget.stringdata0))
        return static_cast<void*>(this);
    return JsonWidget::qt_metacast(_clname);
}

int Avogadro::QtGui::InterfaceWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = JsonWidget::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE

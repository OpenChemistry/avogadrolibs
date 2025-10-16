/****************************************************************************
** Meta object code from reading C++ file 'label.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/label/label.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'label.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__Label_t {
    QByteArrayData data[10];
    char stringdata0[117];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__Label_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__Label_t qt_meta_stringdata_Avogadro__QtPlugins__Label = {
    {
QT_MOC_LITERAL(0, 0, 26), // "Avogadro::QtPlugins::Label"
QT_MOC_LITERAL(1, 27, 13), // "atomLabelType"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 5), // "index"
QT_MOC_LITERAL(4, 48, 13), // "bondLabelType"
QT_MOC_LITERAL(5, 62, 16), // "residueLabelType"
QT_MOC_LITERAL(6, 79, 15), // "setRadiusScalar"
QT_MOC_LITERAL(7, 95, 6), // "radius"
QT_MOC_LITERAL(8, 102, 8), // "setColor"
QT_MOC_LITERAL(9, 111, 5) // "color"

    },
    "Avogadro::QtPlugins::Label\0atomLabelType\0"
    "\0index\0bondLabelType\0residueLabelType\0"
    "setRadiusScalar\0radius\0setColor\0color"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__Label[] = {

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
       1,    1,   39,    2, 0x0a /* Public */,
       4,    1,   42,    2, 0x0a /* Public */,
       5,    1,   45,    2, 0x0a /* Public */,
       6,    1,   48,    2, 0x0a /* Public */,
       8,    1,   51,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Double,    7,
    QMetaType::Void, QMetaType::QColor,    9,

       0        // eod
};

void Avogadro::QtPlugins::Label::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Label *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->atomLabelType((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->bondLabelType((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->residueLabelType((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->setRadiusScalar((*reinterpret_cast< double(*)>(_a[1]))); break;
        case 4: _t->setColor((*reinterpret_cast< const QColor(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::Label::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ScenePlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__Label.data,
    qt_meta_data_Avogadro__QtPlugins__Label,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::Label::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::Label::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__Label.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ScenePlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::Label::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ScenePlugin::qt_metacall(_c, _id, _a);
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

/****************************************************************************
** Meta object code from reading C++ file 'vrml.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/vrml/vrml.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'vrml.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__VRML_t {
    QByteArrayData data[12];
    char stringdata0[136];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__VRML_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__VRML_t qt_meta_stringdata_Avogadro__QtPlugins__VRML = {
    {
QT_MOC_LITERAL(0, 0, 25), // "Avogadro::QtPlugins::VRML"
QT_MOC_LITERAL(1, 26, 11), // "setMolecule"
QT_MOC_LITERAL(2, 38, 0), // ""
QT_MOC_LITERAL(3, 39, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 56, 3), // "mol"
QT_MOC_LITERAL(5, 60, 8), // "setScene"
QT_MOC_LITERAL(6, 69, 17), // "Rendering::Scene*"
QT_MOC_LITERAL(7, 87, 5), // "scene"
QT_MOC_LITERAL(8, 93, 9), // "setCamera"
QT_MOC_LITERAL(9, 103, 18), // "Rendering::Camera*"
QT_MOC_LITERAL(10, 122, 6), // "camera"
QT_MOC_LITERAL(11, 129, 6) // "render"

    },
    "Avogadro::QtPlugins::VRML\0setMolecule\0"
    "\0QtGui::Molecule*\0mol\0setScene\0"
    "Rendering::Scene*\0scene\0setCamera\0"
    "Rendering::Camera*\0camera\0render"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__VRML[] = {

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
       1,    1,   34,    2, 0x0a /* Public */,
       5,    1,   37,    2, 0x0a /* Public */,
       8,    1,   40,    2, 0x0a /* Public */,
      11,    0,   43,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::VRML::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<VRML *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->setScene((*reinterpret_cast< Rendering::Scene*(*)>(_a[1]))); break;
        case 2: _t->setCamera((*reinterpret_cast< Rendering::Camera*(*)>(_a[1]))); break;
        case 3: _t->render(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::VRML::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__VRML.data,
    qt_meta_data_Avogadro__QtPlugins__VRML,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::VRML::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::VRML::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__VRML.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::VRML::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
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

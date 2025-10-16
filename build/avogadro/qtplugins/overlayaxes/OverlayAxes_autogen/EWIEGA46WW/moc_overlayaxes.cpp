/****************************************************************************
** Meta object code from reading C++ file 'overlayaxes.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/overlayaxes/overlayaxes.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'overlayaxes.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes_t {
    QByteArrayData data[13];
    char stringdata0[165];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes_t qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes = {
    {
QT_MOC_LITERAL(0, 0, 32), // "Avogadro::QtPlugins::OverlayAxes"
QT_MOC_LITERAL(1, 33, 15), // "updateRequested"
QT_MOC_LITERAL(2, 49, 0), // ""
QT_MOC_LITERAL(3, 50, 11), // "setMolecule"
QT_MOC_LITERAL(4, 62, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(5, 79, 8), // "molecule"
QT_MOC_LITERAL(6, 88, 8), // "setScene"
QT_MOC_LITERAL(7, 97, 17), // "Rendering::Scene*"
QT_MOC_LITERAL(8, 115, 5), // "scene"
QT_MOC_LITERAL(9, 121, 15), // "setActiveWidget"
QT_MOC_LITERAL(10, 137, 8), // "QWidget*"
QT_MOC_LITERAL(11, 146, 6), // "widget"
QT_MOC_LITERAL(12, 153, 11) // "processAxes"

    },
    "Avogadro::QtPlugins::OverlayAxes\0"
    "updateRequested\0\0setMolecule\0"
    "QtGui::Molecule*\0molecule\0setScene\0"
    "Rendering::Scene*\0scene\0setActiveWidget\0"
    "QWidget*\0widget\0processAxes"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__OverlayAxes[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   39,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    1,   40,    2, 0x0a /* Public */,
       6,    1,   43,    2, 0x0a /* Public */,
       9,    1,   46,    2, 0x0a /* Public */,
      12,    0,   49,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void, 0x80000000 | 7,    8,
    QMetaType::Void, 0x80000000 | 10,   11,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::OverlayAxes::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<OverlayAxes *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->updateRequested(); break;
        case 1: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 2: _t->setScene((*reinterpret_cast< Rendering::Scene*(*)>(_a[1]))); break;
        case 3: _t->setActiveWidget((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 4: _t->processAxes(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (OverlayAxes::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&OverlayAxes::updateRequested)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::OverlayAxes::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes.data,
    qt_meta_data_Avogadro__QtPlugins__OverlayAxes,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::OverlayAxes::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::OverlayAxes::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__OverlayAxes.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::OverlayAxes::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void Avogadro::QtPlugins::OverlayAxes::updateRequested()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

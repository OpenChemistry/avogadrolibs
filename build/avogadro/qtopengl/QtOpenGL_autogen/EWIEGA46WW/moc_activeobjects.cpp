/****************************************************************************
** Meta object code from reading C++ file 'activeobjects.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtopengl/activeobjects.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'activeobjects.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects_t {
    QByteArrayData data[14];
    char stringdata0[212];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects_t qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects = {
    {
QT_MOC_LITERAL(0, 0, 33), // "Avogadro::QtOpenGL::ActiveObj..."
QT_MOC_LITERAL(1, 34, 21), // "activeGLWidgetChanged"
QT_MOC_LITERAL(2, 56, 0), // ""
QT_MOC_LITERAL(3, 57, 9), // "GLWidget*"
QT_MOC_LITERAL(4, 67, 8), // "glWidget"
QT_MOC_LITERAL(5, 76, 19), // "activeWidgetChanged"
QT_MOC_LITERAL(6, 96, 8), // "QWidget*"
QT_MOC_LITERAL(7, 105, 6), // "widget"
QT_MOC_LITERAL(8, 112, 21), // "activeMoleculeChanged"
QT_MOC_LITERAL(9, 134, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(10, 151, 8), // "molecule"
QT_MOC_LITERAL(11, 160, 17), // "setActiveGLWidget"
QT_MOC_LITERAL(12, 178, 15), // "setActiveWidget"
QT_MOC_LITERAL(13, 194, 17) // "setActiveMolecule"

    },
    "Avogadro::QtOpenGL::ActiveObjects\0"
    "activeGLWidgetChanged\0\0GLWidget*\0"
    "glWidget\0activeWidgetChanged\0QWidget*\0"
    "widget\0activeMoleculeChanged\0"
    "QtGui::Molecule*\0molecule\0setActiveGLWidget\0"
    "setActiveWidget\0setActiveMolecule"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtOpenGL__ActiveObjects[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x06 /* Public */,
       5,    1,   47,    2, 0x06 /* Public */,
       8,    1,   50,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      11,    1,   53,    2, 0x0a /* Public */,
      12,    1,   56,    2, 0x0a /* Public */,
      13,    1,   59,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, 0x80000000 | 9,   10,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, 0x80000000 | 9,   10,

       0        // eod
};

void Avogadro::QtOpenGL::ActiveObjects::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ActiveObjects *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->activeGLWidgetChanged((*reinterpret_cast< GLWidget*(*)>(_a[1]))); break;
        case 1: _t->activeWidgetChanged((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 2: _t->activeMoleculeChanged((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 3: _t->setActiveGLWidget((*reinterpret_cast< GLWidget*(*)>(_a[1]))); break;
        case 4: _t->setActiveWidget((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 5: _t->setActiveMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ActiveObjects::*)(GLWidget * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ActiveObjects::activeGLWidgetChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ActiveObjects::*)(QWidget * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ActiveObjects::activeWidgetChanged)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ActiveObjects::*)(QtGui::Molecule * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ActiveObjects::activeMoleculeChanged)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtOpenGL::ActiveObjects::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects.data,
    qt_meta_data_Avogadro__QtOpenGL__ActiveObjects,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtOpenGL::ActiveObjects::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtOpenGL::ActiveObjects::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtOpenGL__ActiveObjects.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::QtOpenGL::ActiveObjects::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtOpenGL::ActiveObjects::activeGLWidgetChanged(GLWidget * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtOpenGL::ActiveObjects::activeWidgetChanged(QWidget * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void Avogadro::QtOpenGL::ActiveObjects::activeMoleculeChanged(QtGui::Molecule * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

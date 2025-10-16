/****************************************************************************
** Meta object code from reading C++ file 'toolplugin.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/toolplugin.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'toolplugin.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__ToolPlugin_t {
    QByteArrayData data[20];
    char stringdata0[299];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__ToolPlugin_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__ToolPlugin_t qt_meta_stringdata_Avogadro__QtGui__ToolPlugin = {
    {
QT_MOC_LITERAL(0, 0, 27), // "Avogadro::QtGui::ToolPlugin"
QT_MOC_LITERAL(1, 28, 16), // "drawablesChanged"
QT_MOC_LITERAL(2, 45, 0), // ""
QT_MOC_LITERAL(3, 46, 15), // "updateRequested"
QT_MOC_LITERAL(4, 62, 15), // "registerCommand"
QT_MOC_LITERAL(5, 78, 7), // "command"
QT_MOC_LITERAL(6, 86, 11), // "description"
QT_MOC_LITERAL(7, 98, 25), // "requestActiveDisplayTypes"
QT_MOC_LITERAL(8, 124, 12), // "displayTypes"
QT_MOC_LITERAL(9, 137, 11), // "setMolecule"
QT_MOC_LITERAL(10, 149, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(11, 166, 3), // "mol"
QT_MOC_LITERAL(12, 170, 15), // "setEditMolecule"
QT_MOC_LITERAL(13, 186, 18), // "QtGui::RWMolecule*"
QT_MOC_LITERAL(14, 205, 11), // "setGLWidget"
QT_MOC_LITERAL(15, 217, 19), // "QtOpenGL::GLWidget*"
QT_MOC_LITERAL(16, 237, 15), // "setActiveWidget"
QT_MOC_LITERAL(17, 253, 8), // "QWidget*"
QT_MOC_LITERAL(18, 262, 13), // "setGLRenderer"
QT_MOC_LITERAL(19, 276, 22) // "Rendering::GLRenderer*"

    },
    "Avogadro::QtGui::ToolPlugin\0"
    "drawablesChanged\0\0updateRequested\0"
    "registerCommand\0command\0description\0"
    "requestActiveDisplayTypes\0displayTypes\0"
    "setMolecule\0QtGui::Molecule*\0mol\0"
    "setEditMolecule\0QtGui::RWMolecule*\0"
    "setGLWidget\0QtOpenGL::GLWidget*\0"
    "setActiveWidget\0QWidget*\0setGLRenderer\0"
    "Rendering::GLRenderer*"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__ToolPlugin[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   59,    2, 0x06 /* Public */,
       3,    0,   60,    2, 0x06 /* Public */,
       4,    2,   61,    2, 0x06 /* Public */,
       7,    1,   66,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    1,   69,    2, 0x0a /* Public */,
      12,    1,   72,    2, 0x0a /* Public */,
      14,    1,   75,    2, 0x0a /* Public */,
      16,    1,   78,    2, 0x0a /* Public */,
      18,    1,   81,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    5,    6,
    QMetaType::Void, QMetaType::QStringList,    8,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 10,   11,
    QMetaType::Void, 0x80000000 | 13,    2,
    QMetaType::Void, 0x80000000 | 15,    2,
    QMetaType::Void, 0x80000000 | 17,    2,
    QMetaType::Void, 0x80000000 | 19,    2,

       0        // eod
};

void Avogadro::QtGui::ToolPlugin::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ToolPlugin *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->drawablesChanged(); break;
        case 1: _t->updateRequested(); break;
        case 2: _t->registerCommand((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 3: _t->requestActiveDisplayTypes((*reinterpret_cast< QStringList(*)>(_a[1]))); break;
        case 4: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 5: _t->setEditMolecule((*reinterpret_cast< QtGui::RWMolecule*(*)>(_a[1]))); break;
        case 6: _t->setGLWidget((*reinterpret_cast< QtOpenGL::GLWidget*(*)>(_a[1]))); break;
        case 7: _t->setActiveWidget((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 8: _t->setGLRenderer((*reinterpret_cast< Rendering::GLRenderer*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ToolPlugin::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ToolPlugin::drawablesChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ToolPlugin::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ToolPlugin::updateRequested)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ToolPlugin::*)(QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ToolPlugin::registerCommand)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (ToolPlugin::*)(QStringList );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ToolPlugin::requestActiveDisplayTypes)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::ToolPlugin::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__ToolPlugin.data,
    qt_meta_data_Avogadro__QtGui__ToolPlugin,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::ToolPlugin::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::ToolPlugin::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__ToolPlugin.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::QtGui::ToolPlugin::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
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
void Avogadro::QtGui::ToolPlugin::drawablesChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Avogadro::QtGui::ToolPlugin::updateRequested()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void Avogadro::QtGui::ToolPlugin::registerCommand(QString _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void Avogadro::QtGui::ToolPlugin::requestActiveDisplayTypes(QStringList _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

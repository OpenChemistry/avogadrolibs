/****************************************************************************
** Meta object code from reading C++ file 'extensionplugin.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/extensionplugin.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'extensionplugin.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin_t {
    QByteArrayData data[28];
    char stringdata0[371];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin_t qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin = {
    {
QT_MOC_LITERAL(0, 0, 32), // "Avogadro::QtGui::ExtensionPlugin"
QT_MOC_LITERAL(1, 33, 13), // "moleculeReady"
QT_MOC_LITERAL(2, 47, 0), // ""
QT_MOC_LITERAL(3, 48, 17), // "numberOfMolecules"
QT_MOC_LITERAL(4, 66, 16), // "fileFormatsReady"
QT_MOC_LITERAL(5, 83, 17), // "requestActiveTool"
QT_MOC_LITERAL(6, 101, 8), // "toolName"
QT_MOC_LITERAL(7, 110, 25), // "requestActiveDisplayTypes"
QT_MOC_LITERAL(8, 136, 12), // "displayTypes"
QT_MOC_LITERAL(9, 149, 15), // "registerCommand"
QT_MOC_LITERAL(10, 165, 7), // "command"
QT_MOC_LITERAL(11, 173, 11), // "description"
QT_MOC_LITERAL(12, 185, 11), // "setMolecule"
QT_MOC_LITERAL(13, 197, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(14, 214, 3), // "mol"
QT_MOC_LITERAL(15, 218, 12), // "readMolecule"
QT_MOC_LITERAL(16, 231, 16), // "QtGui::Molecule&"
QT_MOC_LITERAL(17, 248, 8), // "setScene"
QT_MOC_LITERAL(18, 257, 17), // "Rendering::Scene*"
QT_MOC_LITERAL(19, 275, 5), // "scene"
QT_MOC_LITERAL(20, 281, 9), // "setCamera"
QT_MOC_LITERAL(21, 291, 18), // "Rendering::Camera*"
QT_MOC_LITERAL(22, 310, 6), // "camera"
QT_MOC_LITERAL(23, 317, 15), // "setActiveWidget"
QT_MOC_LITERAL(24, 333, 8), // "QWidget*"
QT_MOC_LITERAL(25, 342, 6), // "widget"
QT_MOC_LITERAL(26, 349, 13), // "handleCommand"
QT_MOC_LITERAL(27, 363, 7) // "options"

    },
    "Avogadro::QtGui::ExtensionPlugin\0"
    "moleculeReady\0\0numberOfMolecules\0"
    "fileFormatsReady\0requestActiveTool\0"
    "toolName\0requestActiveDisplayTypes\0"
    "displayTypes\0registerCommand\0command\0"
    "description\0setMolecule\0QtGui::Molecule*\0"
    "mol\0readMolecule\0QtGui::Molecule&\0"
    "setScene\0Rendering::Scene*\0scene\0"
    "setCamera\0Rendering::Camera*\0camera\0"
    "setActiveWidget\0QWidget*\0widget\0"
    "handleCommand\0options"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__ExtensionPlugin[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       5,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x06 /* Public */,
       4,    0,   72,    2, 0x06 /* Public */,
       5,    1,   73,    2, 0x06 /* Public */,
       7,    1,   76,    2, 0x06 /* Public */,
       9,    2,   79,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      12,    1,   84,    2, 0x0a /* Public */,
      15,    1,   87,    2, 0x0a /* Public */,
      17,    1,   90,    2, 0x0a /* Public */,
      20,    1,   93,    2, 0x0a /* Public */,
      23,    1,   96,    2, 0x0a /* Public */,
      26,    2,   99,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    6,
    QMetaType::Void, QMetaType::QStringList,    8,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   10,   11,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 13,   14,
    QMetaType::Bool, 0x80000000 | 16,   14,
    QMetaType::Void, 0x80000000 | 18,   19,
    QMetaType::Void, 0x80000000 | 21,   22,
    QMetaType::Void, 0x80000000 | 24,   25,
    QMetaType::Bool, QMetaType::QString, QMetaType::QVariantMap,   10,   27,

       0        // eod
};

void Avogadro::QtGui::ExtensionPlugin::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ExtensionPlugin *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->moleculeReady((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->fileFormatsReady(); break;
        case 2: _t->requestActiveTool((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->requestActiveDisplayTypes((*reinterpret_cast< QStringList(*)>(_a[1]))); break;
        case 4: _t->registerCommand((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 5: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 6: { bool _r = _t->readMolecule((*reinterpret_cast< QtGui::Molecule(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 7: _t->setScene((*reinterpret_cast< Rendering::Scene*(*)>(_a[1]))); break;
        case 8: _t->setCamera((*reinterpret_cast< Rendering::Camera*(*)>(_a[1]))); break;
        case 9: _t->setActiveWidget((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 10: { bool _r = _t->handleCommand((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QVariantMap(*)>(_a[2])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ExtensionPlugin::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ExtensionPlugin::moleculeReady)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ExtensionPlugin::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ExtensionPlugin::fileFormatsReady)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (ExtensionPlugin::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ExtensionPlugin::requestActiveTool)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (ExtensionPlugin::*)(QStringList );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ExtensionPlugin::requestActiveDisplayTypes)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (ExtensionPlugin::*)(QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ExtensionPlugin::registerCommand)) {
                *result = 4;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::ExtensionPlugin::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin.data,
    qt_meta_data_Avogadro__QtGui__ExtensionPlugin,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::ExtensionPlugin::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::ExtensionPlugin::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__ExtensionPlugin.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::QtGui::ExtensionPlugin::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 11;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtGui::ExtensionPlugin::moleculeReady(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtGui::ExtensionPlugin::fileFormatsReady()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void Avogadro::QtGui::ExtensionPlugin::requestActiveTool(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void Avogadro::QtGui::ExtensionPlugin::requestActiveDisplayTypes(QStringList _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void Avogadro::QtGui::ExtensionPlugin::registerCommand(QString _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

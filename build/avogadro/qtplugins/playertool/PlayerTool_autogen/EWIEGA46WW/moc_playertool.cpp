/****************************************************************************
** Meta object code from reading C++ file 'playertool.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/playertool/playertool.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'playertool.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool_t {
    QByteArrayData data[21];
    char stringdata0[253];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool_t qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool = {
    {
QT_MOC_LITERAL(0, 0, 31), // "Avogadro::QtPlugins::PlayerTool"
QT_MOC_LITERAL(1, 32, 11), // "setMolecule"
QT_MOC_LITERAL(2, 44, 0), // ""
QT_MOC_LITERAL(3, 45, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 62, 13), // "setGLRenderer"
QT_MOC_LITERAL(5, 76, 22), // "Rendering::GLRenderer*"
QT_MOC_LITERAL(6, 99, 8), // "renderer"
QT_MOC_LITERAL(7, 108, 15), // "setActiveWidget"
QT_MOC_LITERAL(8, 124, 8), // "QWidget*"
QT_MOC_LITERAL(9, 133, 6), // "widget"
QT_MOC_LITERAL(10, 140, 4), // "back"
QT_MOC_LITERAL(11, 145, 7), // "forward"
QT_MOC_LITERAL(12, 153, 4), // "play"
QT_MOC_LITERAL(13, 158, 4), // "stop"
QT_MOC_LITERAL(14, 163, 7), // "animate"
QT_MOC_LITERAL(15, 171, 7), // "advance"
QT_MOC_LITERAL(16, 179, 11), // "recordMovie"
QT_MOC_LITERAL(17, 191, 21), // "sliderPositionChanged"
QT_MOC_LITERAL(18, 213, 1), // "k"
QT_MOC_LITERAL(19, 215, 22), // "spinnerPositionChanged"
QT_MOC_LITERAL(20, 238, 14) // "setSliderLimit"

    },
    "Avogadro::QtPlugins::PlayerTool\0"
    "setMolecule\0\0QtGui::Molecule*\0"
    "setGLRenderer\0Rendering::GLRenderer*\0"
    "renderer\0setActiveWidget\0QWidget*\0"
    "widget\0back\0forward\0play\0stop\0animate\0"
    "advance\0recordMovie\0sliderPositionChanged\0"
    "k\0spinnerPositionChanged\0setSliderLimit"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__PlayerTool[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   79,    2, 0x0a /* Public */,
       4,    1,   82,    2, 0x0a /* Public */,
       7,    1,   85,    2, 0x0a /* Public */,
      10,    0,   88,    2, 0x09 /* Protected */,
      11,    0,   89,    2, 0x09 /* Protected */,
      12,    0,   90,    2, 0x09 /* Protected */,
      13,    0,   91,    2, 0x09 /* Protected */,
      14,    1,   92,    2, 0x09 /* Protected */,
      14,    0,   95,    2, 0x29 /* Protected | MethodCloned */,
      16,    0,   96,    2, 0x09 /* Protected */,
      17,    1,   97,    2, 0x09 /* Protected */,
      19,    1,  100,    2, 0x09 /* Protected */,
      20,    0,  103,    2, 0x09 /* Protected */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void, 0x80000000 | 5,    6,
    QMetaType::Void, 0x80000000 | 8,    9,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   15,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   18,
    QMetaType::Void, QMetaType::Int,   18,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::PlayerTool::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<PlayerTool *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->setGLRenderer((*reinterpret_cast< Rendering::GLRenderer*(*)>(_a[1]))); break;
        case 2: _t->setActiveWidget((*reinterpret_cast< QWidget*(*)>(_a[1]))); break;
        case 3: _t->back(); break;
        case 4: _t->forward(); break;
        case 5: _t->play(); break;
        case 6: _t->stop(); break;
        case 7: _t->animate((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 8: _t->animate(); break;
        case 9: _t->recordMovie(); break;
        case 10: _t->sliderPositionChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 11: _t->spinnerPositionChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 12: _t->setSliderLimit(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::PlayerTool::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ToolPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool.data,
    qt_meta_data_Avogadro__QtPlugins__PlayerTool,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::PlayerTool::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::PlayerTool::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__PlayerTool.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ToolPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::PlayerTool::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ToolPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 13;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

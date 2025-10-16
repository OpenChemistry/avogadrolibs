/****************************************************************************
** Meta object code from reading C++ file 'copypaste.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/copypaste/copypaste.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'copypaste.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste_t {
    QByteArrayData data[15];
    char stringdata0[148];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste_t qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste = {
    {
QT_MOC_LITERAL(0, 0, 30), // "Avogadro::QtPlugins::CopyPaste"
QT_MOC_LITERAL(1, 31, 11), // "setMolecule"
QT_MOC_LITERAL(2, 43, 0), // ""
QT_MOC_LITERAL(3, 44, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 61, 3), // "mol"
QT_MOC_LITERAL(5, 65, 4), // "copy"
QT_MOC_LITERAL(6, 70, 15), // "Io::FileFormat*"
QT_MOC_LITERAL(7, 86, 6), // "format"
QT_MOC_LITERAL(8, 93, 9), // "copyCJSON"
QT_MOC_LITERAL(9, 103, 10), // "copySMILES"
QT_MOC_LITERAL(10, 114, 9), // "copyInChI"
QT_MOC_LITERAL(11, 124, 7), // "copyXYZ"
QT_MOC_LITERAL(12, 132, 3), // "cut"
QT_MOC_LITERAL(13, 136, 5), // "paste"
QT_MOC_LITERAL(14, 142, 5) // "clear"

    },
    "Avogadro::QtPlugins::CopyPaste\0"
    "setMolecule\0\0QtGui::Molecule*\0mol\0"
    "copy\0Io::FileFormat*\0format\0copyCJSON\0"
    "copySMILES\0copyInChI\0copyXYZ\0cut\0paste\0"
    "clear"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__CopyPaste[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   59,    2, 0x0a /* Public */,
       5,    1,   62,    2, 0x08 /* Private */,
       8,    0,   65,    2, 0x08 /* Private */,
       9,    0,   66,    2, 0x08 /* Private */,
      10,    0,   67,    2, 0x08 /* Private */,
      11,    0,   68,    2, 0x08 /* Private */,
      12,    0,   69,    2, 0x08 /* Private */,
      13,    0,   70,    2, 0x08 /* Private */,
      14,    0,   71,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Bool, 0x80000000 | 6,    7,
    QMetaType::Bool,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::CopyPaste::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<CopyPaste *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: { bool _r = _t->copy((*reinterpret_cast< Io::FileFormat*(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 2: { bool _r = _t->copyCJSON();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 3: _t->copySMILES(); break;
        case 4: _t->copyInChI(); break;
        case 5: _t->copyXYZ(); break;
        case 6: _t->cut(); break;
        case 7: _t->paste(); break;
        case 8: _t->clear(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::CopyPaste::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste.data,
    qt_meta_data_Avogadro__QtPlugins__CopyPaste,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::CopyPaste::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::CopyPaste::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__CopyPaste.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::CopyPaste::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE

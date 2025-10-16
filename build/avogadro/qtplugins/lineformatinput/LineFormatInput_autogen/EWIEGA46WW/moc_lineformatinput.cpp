/****************************************************************************
** Meta object code from reading C++ file 'lineformatinput.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/lineformatinput/lineformatinput.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'lineformatinput.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput_t {
    QByteArrayData data[5];
    char stringdata0[78];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput_t qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput = {
    {
QT_MOC_LITERAL(0, 0, 36), // "Avogadro::QtPlugins::LineForm..."
QT_MOC_LITERAL(1, 37, 11), // "setMolecule"
QT_MOC_LITERAL(2, 49, 0), // ""
QT_MOC_LITERAL(3, 50, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 67, 10) // "showDialog"

    },
    "Avogadro::QtPlugins::LineFormatInput\0"
    "setMolecule\0\0QtGui::Molecule*\0showDialog"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__LineFormatInput[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   24,    2, 0x0a /* Public */,
       4,    0,   27,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::LineFormatInput::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<LineFormatInput *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->showDialog(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::LineFormatInput::staticMetaObject = { {
    QMetaObject::SuperData::link<QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput.data,
    qt_meta_data_Avogadro__QtPlugins__LineFormatInput,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::LineFormatInput::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::LineFormatInput::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__LineFormatInput.stringdata0))
        return static_cast<void*>(this);
    return QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::LineFormatInput::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 2;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

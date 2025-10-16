/****************************************************************************
** Meta object code from reading C++ file 'applycolors.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/applycolors/applycolors.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'applycolors.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors_t {
    QByteArrayData data[18];
    char stringdata0[305];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors_t qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors = {
    {
QT_MOC_LITERAL(0, 0, 32), // "Avogadro::QtPlugins::ApplyColors"
QT_MOC_LITERAL(1, 33, 11), // "setMolecule"
QT_MOC_LITERAL(2, 45, 0), // ""
QT_MOC_LITERAL(3, 46, 16), // "QtGui::Molecule*"
QT_MOC_LITERAL(4, 63, 3), // "mol"
QT_MOC_LITERAL(5, 67, 15), // "openColorDialog"
QT_MOC_LITERAL(6, 83, 16), // "applyCustomColor"
QT_MOC_LITERAL(7, 100, 5), // "color"
QT_MOC_LITERAL(8, 106, 19), // "applyDistanceColors"
QT_MOC_LITERAL(9, 126, 16), // "applyIndexColors"
QT_MOC_LITERAL(10, 143, 17), // "applyChargeColors"
QT_MOC_LITERAL(11, 161, 11), // "resetColors"
QT_MOC_LITERAL(12, 173, 22), // "openColorDialogResidue"
QT_MOC_LITERAL(13, 196, 23), // "applyCustomColorResidue"
QT_MOC_LITERAL(14, 220, 16), // "applyAminoColors"
QT_MOC_LITERAL(15, 237, 18), // "applyShapelyColors"
QT_MOC_LITERAL(16, 256, 29), // "applySecondaryStructureColors"
QT_MOC_LITERAL(17, 286, 18) // "resetColorsResidue"

    },
    "Avogadro::QtPlugins::ApplyColors\0"
    "setMolecule\0\0QtGui::Molecule*\0mol\0"
    "openColorDialog\0applyCustomColor\0color\0"
    "applyDistanceColors\0applyIndexColors\0"
    "applyChargeColors\0resetColors\0"
    "openColorDialogResidue\0applyCustomColorResidue\0"
    "applyAminoColors\0applyShapelyColors\0"
    "applySecondaryStructureColors\0"
    "resetColorsResidue"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__ApplyColors[] = {

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
       5,    0,   82,    2, 0x08 /* Private */,
       6,    1,   83,    2, 0x08 /* Private */,
       8,    0,   86,    2, 0x08 /* Private */,
       9,    0,   87,    2, 0x08 /* Private */,
      10,    0,   88,    2, 0x08 /* Private */,
      11,    0,   89,    2, 0x08 /* Private */,
      12,    0,   90,    2, 0x08 /* Private */,
      13,    1,   91,    2, 0x08 /* Private */,
      14,    0,   94,    2, 0x08 /* Private */,
      15,    0,   95,    2, 0x08 /* Private */,
      16,    0,   96,    2, 0x08 /* Private */,
      17,    0,   97,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QColor,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QColor,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtPlugins::ApplyColors::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ApplyColors *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->setMolecule((*reinterpret_cast< QtGui::Molecule*(*)>(_a[1]))); break;
        case 1: _t->openColorDialog(); break;
        case 2: _t->applyCustomColor((*reinterpret_cast< const QColor(*)>(_a[1]))); break;
        case 3: _t->applyDistanceColors(); break;
        case 4: _t->applyIndexColors(); break;
        case 5: _t->applyChargeColors(); break;
        case 6: _t->resetColors(); break;
        case 7: _t->openColorDialogResidue(); break;
        case 8: _t->applyCustomColorResidue((*reinterpret_cast< const QColor(*)>(_a[1]))); break;
        case 9: _t->applyAminoColors(); break;
        case 10: _t->applyShapelyColors(); break;
        case 11: _t->applySecondaryStructureColors(); break;
        case 12: _t->resetColorsResidue(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::ApplyColors::staticMetaObject = { {
    QMetaObject::SuperData::link<Avogadro::QtGui::ExtensionPlugin::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors.data,
    qt_meta_data_Avogadro__QtPlugins__ApplyColors,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::ApplyColors::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::ApplyColors::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__ApplyColors.stringdata0))
        return static_cast<void*>(this);
    return Avogadro::QtGui::ExtensionPlugin::qt_metacast(_clname);
}

int Avogadro::QtPlugins::ApplyColors::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = Avogadro::QtGui::ExtensionPlugin::qt_metacall(_c, _id, _a);
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

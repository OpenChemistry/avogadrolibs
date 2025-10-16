/****************************************************************************
** Meta object code from reading C++ file 'symmetrywidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../../avogadro/qtplugins/symmetry/symmetrywidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'symmetrywidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget_t {
    QByteArrayData data[33];
    char stringdata0[503];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget_t qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget = {
    {
QT_MOC_LITERAL(0, 0, 35), // "Avogadro::QtPlugins::Symmetry..."
QT_MOC_LITERAL(1, 36, 14), // "detectSymmetry"
QT_MOC_LITERAL(2, 51, 0), // ""
QT_MOC_LITERAL(3, 52, 18), // "symmetrizeMolecule"
QT_MOC_LITERAL(4, 71, 15), // "moleculeChanged"
QT_MOC_LITERAL(5, 87, 7), // "changes"
QT_MOC_LITERAL(6, 95, 19), // "setPointGroupSymbol"
QT_MOC_LITERAL(7, 115, 2), // "pg"
QT_MOC_LITERAL(8, 118, 18), // "setEquivalenceSets"
QT_MOC_LITERAL(9, 137, 4), // "mesl"
QT_MOC_LITERAL(10, 142, 35), // "const msym::msym_equivalence_..."
QT_MOC_LITERAL(11, 178, 2), // "es"
QT_MOC_LITERAL(12, 181, 21), // "setSymmetryOperations"
QT_MOC_LITERAL(13, 203, 5), // "sopsl"
QT_MOC_LITERAL(14, 209, 38), // "const msym::msym_symmetry_ope..."
QT_MOC_LITERAL(15, 248, 4), // "sops"
QT_MOC_LITERAL(16, 253, 12), // "setSubgroups"
QT_MOC_LITERAL(17, 266, 3), // "sgl"
QT_MOC_LITERAL(18, 270, 28), // "const msym::msym_subgroup_t*"
QT_MOC_LITERAL(19, 299, 2), // "sg"
QT_MOC_LITERAL(20, 302, 15), // "setCenterOfMass"
QT_MOC_LITERAL(21, 318, 9), // "double[3]"
QT_MOC_LITERAL(22, 328, 2), // "cm"
QT_MOC_LITERAL(23, 331, 9), // "setRadius"
QT_MOC_LITERAL(24, 341, 6), // "radius"
QT_MOC_LITERAL(25, 348, 13), // "getThresholds"
QT_MOC_LITERAL(26, 362, 24), // "msym::msym_thresholds_t*"
QT_MOC_LITERAL(27, 387, 27), // "equivalenceSelectionChanged"
QT_MOC_LITERAL(28, 415, 14), // "QItemSelection"
QT_MOC_LITERAL(29, 430, 8), // "selected"
QT_MOC_LITERAL(30, 439, 10), // "deselected"
QT_MOC_LITERAL(31, 450, 26), // "operationsSelectionChanged"
QT_MOC_LITERAL(32, 477, 25) // "subgroupsSelectionChanged"

    },
    "Avogadro::QtPlugins::SymmetryWidget\0"
    "detectSymmetry\0\0symmetrizeMolecule\0"
    "moleculeChanged\0changes\0setPointGroupSymbol\0"
    "pg\0setEquivalenceSets\0mesl\0"
    "const msym::msym_equivalence_set_t*\0"
    "es\0setSymmetryOperations\0sopsl\0"
    "const msym::msym_symmetry_operation_t*\0"
    "sops\0setSubgroups\0sgl\0"
    "const msym::msym_subgroup_t*\0sg\0"
    "setCenterOfMass\0double[3]\0cm\0setRadius\0"
    "radius\0getThresholds\0msym::msym_thresholds_t*\0"
    "equivalenceSelectionChanged\0QItemSelection\0"
    "selected\0deselected\0operationsSelectionChanged\0"
    "subgroupsSelectionChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtPlugins__SymmetryWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   79,    2, 0x06 /* Public */,
       3,    0,   80,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    1,   81,    2, 0x0a /* Public */,
       6,    1,   84,    2, 0x0a /* Public */,
       8,    2,   87,    2, 0x0a /* Public */,
      12,    2,   92,    2, 0x0a /* Public */,
      16,    2,   97,    2, 0x0a /* Public */,
      20,    1,  102,    2, 0x0a /* Public */,
      23,    1,  105,    2, 0x0a /* Public */,
      25,    0,  108,    2, 0x0a /* Public */,
      27,    2,  109,    2, 0x08 /* Private */,
      31,    2,  114,    2, 0x08 /* Private */,
      32,    2,  119,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::UInt,    5,
    QMetaType::Void, QMetaType::QString,    7,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 10,    9,   11,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 14,   13,   15,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 18,   17,   19,
    QMetaType::Void, 0x80000000 | 21,   22,
    QMetaType::Void, QMetaType::Double,   24,
    0x80000000 | 26,
    QMetaType::Void, 0x80000000 | 28, 0x80000000 | 28,   29,   30,
    QMetaType::Void, 0x80000000 | 28, 0x80000000 | 28,   29,   30,
    QMetaType::Void, 0x80000000 | 28, 0x80000000 | 28,   29,   30,

       0        // eod
};

void Avogadro::QtPlugins::SymmetryWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<SymmetryWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->detectSymmetry(); break;
        case 1: _t->symmetrizeMolecule(); break;
        case 2: _t->moleculeChanged((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 3: _t->setPointGroupSymbol((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: _t->setEquivalenceSets((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const msym::msym_equivalence_set_t*(*)>(_a[2]))); break;
        case 5: _t->setSymmetryOperations((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const msym::msym_symmetry_operation_t*(*)>(_a[2]))); break;
        case 6: _t->setSubgroups((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const msym::msym_subgroup_t*(*)>(_a[2]))); break;
        case 7: _t->setCenterOfMass((*reinterpret_cast< double(*)[3]>(_a[1]))); break;
        case 8: _t->setRadius((*reinterpret_cast< double(*)>(_a[1]))); break;
        case 9: { msym::msym_thresholds_t* _r = _t->getThresholds();
            if (_a[0]) *reinterpret_cast< msym::msym_thresholds_t**>(_a[0]) = std::move(_r); }  break;
        case 10: _t->equivalenceSelectionChanged((*reinterpret_cast< const QItemSelection(*)>(_a[1])),(*reinterpret_cast< const QItemSelection(*)>(_a[2]))); break;
        case 11: _t->operationsSelectionChanged((*reinterpret_cast< const QItemSelection(*)>(_a[1])),(*reinterpret_cast< const QItemSelection(*)>(_a[2]))); break;
        case 12: _t->subgroupsSelectionChanged((*reinterpret_cast< const QItemSelection(*)>(_a[1])),(*reinterpret_cast< const QItemSelection(*)>(_a[2]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 10:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 1:
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QItemSelection >(); break;
            }
            break;
        case 11:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 1:
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QItemSelection >(); break;
            }
            break;
        case 12:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 1:
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QItemSelection >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (SymmetryWidget::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SymmetryWidget::detectSymmetry)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (SymmetryWidget::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SymmetryWidget::symmetrizeMolecule)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtPlugins::SymmetryWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget.data,
    qt_meta_data_Avogadro__QtPlugins__SymmetryWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtPlugins::SymmetryWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtPlugins::SymmetryWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtPlugins__SymmetryWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Avogadro::QtPlugins::SymmetryWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::QtPlugins::SymmetryWidget::detectSymmetry()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Avogadro::QtPlugins::SymmetryWidget::symmetrizeMolecule()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

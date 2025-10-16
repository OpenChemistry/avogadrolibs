/****************************************************************************
** Meta object code from reading C++ file 'scenepluginmodel.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/qtgui/scenepluginmodel.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'scenepluginmodel.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel_t {
    QByteArrayData data[9];
    char stringdata0[140];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel_t qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel = {
    {
QT_MOC_LITERAL(0, 0, 33), // "Avogadro::QtGui::ScenePluginM..."
QT_MOC_LITERAL(1, 34, 18), // "pluginStateChanged"
QT_MOC_LITERAL(2, 53, 0), // ""
QT_MOC_LITERAL(3, 54, 29), // "Avogadro::QtGui::ScenePlugin*"
QT_MOC_LITERAL(4, 84, 19), // "pluginConfigChanged"
QT_MOC_LITERAL(5, 104, 7), // "addItem"
QT_MOC_LITERAL(6, 112, 4), // "item"
QT_MOC_LITERAL(7, 117, 10), // "removeItem"
QT_MOC_LITERAL(8, 128, 11) // "itemChanged"

    },
    "Avogadro::QtGui::ScenePluginModel\0"
    "pluginStateChanged\0\0Avogadro::QtGui::ScenePlugin*\0"
    "pluginConfigChanged\0addItem\0item\0"
    "removeItem\0itemChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__QtGui__ScenePluginModel[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   39,    2, 0x06 /* Public */,
       4,    0,   42,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   43,    2, 0x0a /* Public */,
       7,    1,   46,    2, 0x0a /* Public */,
       8,    0,   49,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    6,
    QMetaType::Void, 0x80000000 | 3,    6,
    QMetaType::Void,

       0        // eod
};

void Avogadro::QtGui::ScenePluginModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ScenePluginModel *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->pluginStateChanged((*reinterpret_cast< Avogadro::QtGui::ScenePlugin*(*)>(_a[1]))); break;
        case 1: _t->pluginConfigChanged(); break;
        case 2: _t->addItem((*reinterpret_cast< Avogadro::QtGui::ScenePlugin*(*)>(_a[1]))); break;
        case 3: _t->removeItem((*reinterpret_cast< Avogadro::QtGui::ScenePlugin*(*)>(_a[1]))); break;
        case 4: _t->itemChanged(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ScenePluginModel::*)(Avogadro::QtGui::ScenePlugin * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ScenePluginModel::pluginStateChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ScenePluginModel::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ScenePluginModel::pluginConfigChanged)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::QtGui::ScenePluginModel::staticMetaObject = { {
    QMetaObject::SuperData::link<QAbstractItemModel::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel.data,
    qt_meta_data_Avogadro__QtGui__ScenePluginModel,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::QtGui::ScenePluginModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::QtGui::ScenePluginModel::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__QtGui__ScenePluginModel.stringdata0))
        return static_cast<void*>(this);
    return QAbstractItemModel::qt_metacast(_clname);
}

int Avogadro::QtGui::ScenePluginModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QAbstractItemModel::qt_metacall(_c, _id, _a);
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
void Avogadro::QtGui::ScenePluginModel::pluginStateChanged(Avogadro::QtGui::ScenePlugin * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::QtGui::ScenePluginModel::pluginConfigChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

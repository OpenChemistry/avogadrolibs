/****************************************************************************
** Meta object code from reading C++ file 'jsonrpcclient.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/molequeue/client/jsonrpcclient.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'jsonrpcclient.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient_t {
    QByteArrayData data[19];
    char stringdata0[246];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient_t qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient = {
    {
QT_MOC_LITERAL(0, 0, 34), // "Avogadro::MoleQueue::JsonRpcC..."
QT_MOC_LITERAL(1, 35, 22), // "connectionStateChanged"
QT_MOC_LITERAL(2, 58, 0), // ""
QT_MOC_LITERAL(3, 59, 14), // "resultReceived"
QT_MOC_LITERAL(4, 74, 7), // "message"
QT_MOC_LITERAL(5, 82, 20), // "notificationReceived"
QT_MOC_LITERAL(6, 103, 13), // "errorReceived"
QT_MOC_LITERAL(7, 117, 17), // "badPacketReceived"
QT_MOC_LITERAL(8, 135, 5), // "error"
QT_MOC_LITERAL(9, 141, 9), // "newPacket"
QT_MOC_LITERAL(10, 151, 6), // "packet"
QT_MOC_LITERAL(11, 158, 15), // "connectToServer"
QT_MOC_LITERAL(12, 174, 10), // "serverName"
QT_MOC_LITERAL(13, 185, 5), // "flush"
QT_MOC_LITERAL(14, 191, 12), // "emptyRequest"
QT_MOC_LITERAL(15, 204, 11), // "sendRequest"
QT_MOC_LITERAL(16, 216, 7), // "request"
QT_MOC_LITERAL(17, 224, 10), // "readPacket"
QT_MOC_LITERAL(18, 235, 10) // "readSocket"

    },
    "Avogadro::MoleQueue::JsonRpcClient\0"
    "connectionStateChanged\0\0resultReceived\0"
    "message\0notificationReceived\0errorReceived\0"
    "badPacketReceived\0error\0newPacket\0"
    "packet\0connectToServer\0serverName\0"
    "flush\0emptyRequest\0sendRequest\0request\0"
    "readPacket\0readSocket"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__MoleQueue__JsonRpcClient[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      12,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       6,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   74,    2, 0x06 /* Public */,
       3,    1,   75,    2, 0x06 /* Public */,
       5,    1,   78,    2, 0x06 /* Public */,
       6,    1,   81,    2, 0x06 /* Public */,
       7,    1,   84,    2, 0x06 /* Public */,
       9,    1,   87,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      11,    1,   90,    2, 0x0a /* Public */,
      13,    0,   93,    2, 0x0a /* Public */,
      14,    0,   94,    2, 0x0a /* Public */,
      15,    1,   95,    2, 0x0a /* Public */,
      17,    1,   98,    2, 0x09 /* Protected */,
      18,    0,  101,    2, 0x09 /* Protected */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QJsonObject,    4,
    QMetaType::Void, QMetaType::QJsonObject,    4,
    QMetaType::Void, QMetaType::QJsonObject,    4,
    QMetaType::Void, QMetaType::QString,    8,
    QMetaType::Void, QMetaType::QByteArray,   10,

 // slots: parameters
    QMetaType::Bool, QMetaType::QString,   12,
    QMetaType::Void,
    QMetaType::QJsonObject,
    QMetaType::Bool, QMetaType::QJsonObject,   16,
    QMetaType::Void, QMetaType::QByteArray,    4,
    QMetaType::Void,

       0        // eod
};

void Avogadro::MoleQueue::JsonRpcClient::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<JsonRpcClient *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->connectionStateChanged(); break;
        case 1: _t->resultReceived((*reinterpret_cast< QJsonObject(*)>(_a[1]))); break;
        case 2: _t->notificationReceived((*reinterpret_cast< QJsonObject(*)>(_a[1]))); break;
        case 3: _t->errorReceived((*reinterpret_cast< QJsonObject(*)>(_a[1]))); break;
        case 4: _t->badPacketReceived((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 5: _t->newPacket((*reinterpret_cast< const QByteArray(*)>(_a[1]))); break;
        case 6: { bool _r = _t->connectToServer((*reinterpret_cast< const QString(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 7: _t->flush(); break;
        case 8: { QJsonObject _r = _t->emptyRequest();
            if (_a[0]) *reinterpret_cast< QJsonObject*>(_a[0]) = std::move(_r); }  break;
        case 9: { bool _r = _t->sendRequest((*reinterpret_cast< const QJsonObject(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 10: _t->readPacket((*reinterpret_cast< const QByteArray(*)>(_a[1]))); break;
        case 11: _t->readSocket(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (JsonRpcClient::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::connectionStateChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (JsonRpcClient::*)(QJsonObject );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::resultReceived)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (JsonRpcClient::*)(QJsonObject );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::notificationReceived)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (JsonRpcClient::*)(QJsonObject );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::errorReceived)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (JsonRpcClient::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::badPacketReceived)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (JsonRpcClient::*)(const QByteArray & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&JsonRpcClient::newPacket)) {
                *result = 5;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::MoleQueue::JsonRpcClient::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient.data,
    qt_meta_data_Avogadro__MoleQueue__JsonRpcClient,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::MoleQueue::JsonRpcClient::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::MoleQueue::JsonRpcClient::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__MoleQueue__JsonRpcClient.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::MoleQueue::JsonRpcClient::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 12)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::MoleQueue::JsonRpcClient::connectionStateChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Avogadro::MoleQueue::JsonRpcClient::resultReceived(QJsonObject _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void Avogadro::MoleQueue::JsonRpcClient::notificationReceived(QJsonObject _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void Avogadro::MoleQueue::JsonRpcClient::errorReceived(QJsonObject _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void Avogadro::MoleQueue::JsonRpcClient::badPacketReceived(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void Avogadro::MoleQueue::JsonRpcClient::newPacket(const QByteArray & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

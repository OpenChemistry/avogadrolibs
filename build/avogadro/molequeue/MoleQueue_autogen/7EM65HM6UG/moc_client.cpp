/****************************************************************************
** Meta object code from reading C++ file 'client.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/molequeue/client/client.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#include <QtCore/QList>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'client.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__MoleQueue__Client_t {
    QByteArrayData data[46];
    char stringdata0[635];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__MoleQueue__Client_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__MoleQueue__Client_t qt_meta_stringdata_Avogadro__MoleQueue__Client = {
    {
QT_MOC_LITERAL(0, 0, 27), // "Avogadro::MoleQueue::Client"
QT_MOC_LITERAL(1, 28, 22), // "connectionStateChanged"
QT_MOC_LITERAL(2, 51, 0), // ""
QT_MOC_LITERAL(3, 52, 17), // "queueListReceived"
QT_MOC_LITERAL(4, 70, 6), // "queues"
QT_MOC_LITERAL(5, 77, 17), // "submitJobResponse"
QT_MOC_LITERAL(6, 95, 7), // "localId"
QT_MOC_LITERAL(7, 103, 11), // "moleQueueId"
QT_MOC_LITERAL(8, 115, 17), // "lookupJobResponse"
QT_MOC_LITERAL(9, 133, 7), // "jobInfo"
QT_MOC_LITERAL(10, 141, 17), // "cancelJobResponse"
QT_MOC_LITERAL(11, 159, 15), // "jobStateChanged"
QT_MOC_LITERAL(12, 175, 8), // "oldState"
QT_MOC_LITERAL(13, 184, 8), // "newState"
QT_MOC_LITERAL(14, 193, 24), // "registerOpenWithResponse"
QT_MOC_LITERAL(15, 218, 25), // "listOpenWithNamesResponse"
QT_MOC_LITERAL(16, 244, 12), // "handlerNames"
QT_MOC_LITERAL(17, 257, 26), // "unregisterOpenWithResponse"
QT_MOC_LITERAL(18, 284, 13), // "errorReceived"
QT_MOC_LITERAL(19, 298, 9), // "errorCode"
QT_MOC_LITERAL(20, 308, 12), // "errorMessage"
QT_MOC_LITERAL(21, 321, 9), // "errorData"
QT_MOC_LITERAL(22, 331, 15), // "connectToServer"
QT_MOC_LITERAL(23, 347, 10), // "serverName"
QT_MOC_LITERAL(24, 358, 16), // "requestQueueList"
QT_MOC_LITERAL(25, 375, 9), // "submitJob"
QT_MOC_LITERAL(26, 385, 9), // "JobObject"
QT_MOC_LITERAL(27, 395, 3), // "job"
QT_MOC_LITERAL(28, 399, 9), // "lookupJob"
QT_MOC_LITERAL(29, 409, 9), // "cancelJob"
QT_MOC_LITERAL(30, 419, 16), // "registerOpenWith"
QT_MOC_LITERAL(31, 436, 4), // "name"
QT_MOC_LITERAL(32, 441, 10), // "executable"
QT_MOC_LITERAL(33, 452, 25), // "QList<QRegularExpression>"
QT_MOC_LITERAL(34, 478, 12), // "filePatterns"
QT_MOC_LITERAL(35, 491, 9), // "rpcServer"
QT_MOC_LITERAL(36, 501, 9), // "rpcMethod"
QT_MOC_LITERAL(37, 511, 17), // "listOpenWithNames"
QT_MOC_LITERAL(38, 529, 18), // "unregisterOpenWith"
QT_MOC_LITERAL(39, 548, 11), // "handlerName"
QT_MOC_LITERAL(40, 560, 5), // "flush"
QT_MOC_LITERAL(41, 566, 13), // "processResult"
QT_MOC_LITERAL(42, 580, 8), // "response"
QT_MOC_LITERAL(43, 589, 19), // "processNotification"
QT_MOC_LITERAL(44, 609, 12), // "notification"
QT_MOC_LITERAL(45, 622, 12) // "processError"

    },
    "Avogadro::MoleQueue::Client\0"
    "connectionStateChanged\0\0queueListReceived\0"
    "queues\0submitJobResponse\0localId\0"
    "moleQueueId\0lookupJobResponse\0jobInfo\0"
    "cancelJobResponse\0jobStateChanged\0"
    "oldState\0newState\0registerOpenWithResponse\0"
    "listOpenWithNamesResponse\0handlerNames\0"
    "unregisterOpenWithResponse\0errorReceived\0"
    "errorCode\0errorMessage\0errorData\0"
    "connectToServer\0serverName\0requestQueueList\0"
    "submitJob\0JobObject\0job\0lookupJob\0"
    "cancelJob\0registerOpenWith\0name\0"
    "executable\0QList<QRegularExpression>\0"
    "filePatterns\0rpcServer\0rpcMethod\0"
    "listOpenWithNames\0unregisterOpenWith\0"
    "handlerName\0flush\0processResult\0"
    "response\0processNotification\0notification\0"
    "processError"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__MoleQueue__Client[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      24,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      10,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,  134,    2, 0x06 /* Public */,
       3,    1,  135,    2, 0x06 /* Public */,
       5,    2,  138,    2, 0x06 /* Public */,
       8,    2,  143,    2, 0x06 /* Public */,
      10,    1,  148,    2, 0x06 /* Public */,
      11,    3,  151,    2, 0x06 /* Public */,
      14,    1,  158,    2, 0x06 /* Public */,
      15,    2,  161,    2, 0x06 /* Public */,
      17,    1,  166,    2, 0x06 /* Public */,
      18,    4,  169,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      22,    1,  178,    2, 0x0a /* Public */,
      22,    0,  181,    2, 0x2a /* Public | MethodCloned */,
      24,    0,  182,    2, 0x0a /* Public */,
      25,    1,  183,    2, 0x0a /* Public */,
      28,    1,  186,    2, 0x0a /* Public */,
      29,    1,  189,    2, 0x0a /* Public */,
      30,    3,  192,    2, 0x0a /* Public */,
      30,    4,  199,    2, 0x0a /* Public */,
      37,    0,  208,    2, 0x0a /* Public */,
      38,    1,  209,    2, 0x0a /* Public */,
      40,    0,  212,    2, 0x0a /* Public */,
      41,    1,  213,    2, 0x09 /* Protected */,
      43,    1,  216,    2, 0x09 /* Protected */,
      45,    1,  219,    2, 0x09 /* Protected */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QJsonObject,    4,
    QMetaType::Void, QMetaType::Int, QMetaType::UInt,    6,    7,
    QMetaType::Void, QMetaType::Int, QMetaType::QJsonObject,    6,    9,
    QMetaType::Void, QMetaType::UInt,    7,
    QMetaType::Void, QMetaType::UInt, QMetaType::QString, QMetaType::QString,    7,   12,   13,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::Int, QMetaType::QJsonArray,    6,   16,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::Int, QMetaType::Int, QMetaType::QString, QMetaType::QJsonValue,    6,   19,   20,   21,

 // slots: parameters
    QMetaType::Bool, QMetaType::QString,   23,
    QMetaType::Bool,
    QMetaType::Int,
    QMetaType::Int, 0x80000000 | 26,   27,
    QMetaType::Int, QMetaType::UInt,    7,
    QMetaType::Int, QMetaType::UInt,    7,
    QMetaType::Int, QMetaType::QString, QMetaType::QString, 0x80000000 | 33,   31,   32,   34,
    QMetaType::Int, QMetaType::QString, QMetaType::QString, QMetaType::QString, 0x80000000 | 33,   31,   35,   36,   34,
    QMetaType::Int,
    QMetaType::Int, QMetaType::QString,   39,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QJsonObject,   42,
    QMetaType::Void, QMetaType::QJsonObject,   44,
    QMetaType::Void, QMetaType::QJsonObject,   44,

       0        // eod
};

void Avogadro::MoleQueue::Client::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<Client *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->connectionStateChanged(); break;
        case 1: _t->queueListReceived((*reinterpret_cast< QJsonObject(*)>(_a[1]))); break;
        case 2: _t->submitJobResponse((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< uint(*)>(_a[2]))); break;
        case 3: _t->lookupJobResponse((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< QJsonObject(*)>(_a[2]))); break;
        case 4: _t->cancelJobResponse((*reinterpret_cast< uint(*)>(_a[1]))); break;
        case 5: _t->jobStateChanged((*reinterpret_cast< uint(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 6: _t->registerOpenWithResponse((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->listOpenWithNamesResponse((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< QJsonArray(*)>(_a[2]))); break;
        case 8: _t->unregisterOpenWithResponse((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 9: _t->errorReceived((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3])),(*reinterpret_cast< QJsonValue(*)>(_a[4]))); break;
        case 10: { bool _r = _t->connectToServer((*reinterpret_cast< const QString(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 11: { bool _r = _t->connectToServer();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 12: { int _r = _t->requestQueueList();
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 13: { int _r = _t->submitJob((*reinterpret_cast< const JobObject(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 14: { int _r = _t->lookupJob((*reinterpret_cast< uint(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 15: { int _r = _t->cancelJob((*reinterpret_cast< uint(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 16: { int _r = _t->registerOpenWith((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QList<QRegularExpression>(*)>(_a[3])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 17: { int _r = _t->registerOpenWith((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QList<QRegularExpression>(*)>(_a[4])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 18: { int _r = _t->listOpenWithNames();
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 19: { int _r = _t->unregisterOpenWith((*reinterpret_cast< const QString(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 20: _t->flush(); break;
        case 21: _t->processResult((*reinterpret_cast< const QJsonObject(*)>(_a[1]))); break;
        case 22: _t->processNotification((*reinterpret_cast< const QJsonObject(*)>(_a[1]))); break;
        case 23: _t->processError((*reinterpret_cast< const QJsonObject(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 16:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 2:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QList<QRegularExpression> >(); break;
            }
            break;
        case 17:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 3:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QList<QRegularExpression> >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (Client::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::connectionStateChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (Client::*)(QJsonObject );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::queueListReceived)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (Client::*)(int , unsigned int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::submitJobResponse)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (Client::*)(int , QJsonObject );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::lookupJobResponse)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (Client::*)(unsigned int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::cancelJobResponse)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (Client::*)(unsigned int , QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::jobStateChanged)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (Client::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::registerOpenWithResponse)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (Client::*)(int , QJsonArray );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::listOpenWithNamesResponse)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (Client::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::unregisterOpenWithResponse)) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (Client::*)(int , int , QString , QJsonValue );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::errorReceived)) {
                *result = 9;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::MoleQueue::Client::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__MoleQueue__Client.data,
    qt_meta_data_Avogadro__MoleQueue__Client,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::MoleQueue::Client::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::MoleQueue::Client::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__MoleQueue__Client.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::MoleQueue::Client::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 24)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 24;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 24)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 24;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::MoleQueue::Client::connectionStateChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void Avogadro::MoleQueue::Client::queueListReceived(QJsonObject _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void Avogadro::MoleQueue::Client::submitJobResponse(int _t1, unsigned int _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void Avogadro::MoleQueue::Client::lookupJobResponse(int _t1, QJsonObject _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void Avogadro::MoleQueue::Client::cancelJobResponse(unsigned int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void Avogadro::MoleQueue::Client::jobStateChanged(unsigned int _t1, QString _t2, QString _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void Avogadro::MoleQueue::Client::registerOpenWithResponse(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void Avogadro::MoleQueue::Client::listOpenWithNamesResponse(int _t1, QJsonArray _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 7, _a);
}

// SIGNAL 8
void Avogadro::MoleQueue::Client::unregisterOpenWithResponse(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}

// SIGNAL 9
void Avogadro::MoleQueue::Client::errorReceived(int _t1, int _t2, QString _t3, QJsonValue _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t3))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t4))) };
    QMetaObject::activate(this, &staticMetaObject, 9, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

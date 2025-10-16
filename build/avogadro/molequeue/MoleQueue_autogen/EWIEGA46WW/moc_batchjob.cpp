/****************************************************************************
** Meta object code from reading C++ file 'batchjob.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/molequeue/batchjob.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'batchjob.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__MoleQueue__BatchJob_t {
    QByteArrayData data[26];
    char stringdata0[370];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__MoleQueue__BatchJob_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__MoleQueue__BatchJob_t qt_meta_stringdata_Avogadro__MoleQueue__BatchJob = {
    {
QT_MOC_LITERAL(0, 0, 29), // "Avogadro::MoleQueue::BatchJob"
QT_MOC_LITERAL(1, 30, 10), // "jobUpdated"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 38), // "Avogadro::MoleQueue::BatchJob..."
QT_MOC_LITERAL(4, 81, 7), // "batchId"
QT_MOC_LITERAL(5, 89, 7), // "success"
QT_MOC_LITERAL(6, 97, 12), // "jobCompleted"
QT_MOC_LITERAL(7, 110, 39), // "Avogadro::MoleQueue::BatchJob..."
QT_MOC_LITERAL(8, 150, 6), // "status"
QT_MOC_LITERAL(9, 157, 13), // "submitNextJob"
QT_MOC_LITERAL(10, 171, 7), // "BatchId"
QT_MOC_LITERAL(11, 179, 14), // "Core::Molecule"
QT_MOC_LITERAL(12, 194, 3), // "mol"
QT_MOC_LITERAL(13, 198, 9), // "lookupJob"
QT_MOC_LITERAL(14, 208, 21), // "handleSubmissionReply"
QT_MOC_LITERAL(15, 230, 9), // "requestId"
QT_MOC_LITERAL(16, 240, 8), // "serverId"
QT_MOC_LITERAL(17, 249, 20), // "handleJobStateChange"
QT_MOC_LITERAL(18, 270, 8), // "oldState"
QT_MOC_LITERAL(19, 279, 8), // "newState"
QT_MOC_LITERAL(20, 288, 20), // "handleLookupJobReply"
QT_MOC_LITERAL(21, 309, 7), // "jobInfo"
QT_MOC_LITERAL(22, 317, 19), // "handleErrorResponse"
QT_MOC_LITERAL(23, 337, 9), // "errorCode"
QT_MOC_LITERAL(24, 347, 12), // "errorMessage"
QT_MOC_LITERAL(25, 360, 9) // "errorData"

    },
    "Avogadro::MoleQueue::BatchJob\0jobUpdated\0"
    "\0Avogadro::MoleQueue::BatchJob::BatchId\0"
    "batchId\0success\0jobCompleted\0"
    "Avogadro::MoleQueue::BatchJob::JobState\0"
    "status\0submitNextJob\0BatchId\0"
    "Core::Molecule\0mol\0lookupJob\0"
    "handleSubmissionReply\0requestId\0"
    "serverId\0handleJobStateChange\0oldState\0"
    "newState\0handleLookupJobReply\0jobInfo\0"
    "handleErrorResponse\0errorCode\0"
    "errorMessage\0errorData"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__MoleQueue__BatchJob[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   54,    2, 0x06 /* Public */,
       6,    2,   59,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    1,   64,    2, 0x0a /* Public */,
      13,    1,   67,    2, 0x0a /* Public */,
      14,    2,   70,    2, 0x08 /* Private */,
      17,    3,   75,    2, 0x08 /* Private */,
      20,    2,   82,    2, 0x08 /* Private */,
      22,    4,   87,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3, QMetaType::Bool,    4,    5,
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 7,    4,    8,

 // slots: parameters
    0x80000000 | 10, 0x80000000 | 11,   12,
    QMetaType::Bool, 0x80000000 | 10,    4,
    QMetaType::Void, QMetaType::Int, QMetaType::UInt,   15,   16,
    QMetaType::Void, QMetaType::UInt, QMetaType::QString, QMetaType::QString,   16,   18,   19,
    QMetaType::Void, QMetaType::Int, QMetaType::QJsonObject,   15,   21,
    QMetaType::Void, QMetaType::Int, QMetaType::Int, QMetaType::QString, QMetaType::QJsonValue,   15,   23,   24,   25,

       0        // eod
};

void Avogadro::MoleQueue::BatchJob::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<BatchJob *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->jobUpdated((*reinterpret_cast< Avogadro::MoleQueue::BatchJob::BatchId(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 1: _t->jobCompleted((*reinterpret_cast< Avogadro::MoleQueue::BatchJob::BatchId(*)>(_a[1])),(*reinterpret_cast< Avogadro::MoleQueue::BatchJob::JobState(*)>(_a[2]))); break;
        case 2: { BatchId _r = _t->submitNextJob((*reinterpret_cast< const Core::Molecule(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< BatchId*>(_a[0]) = std::move(_r); }  break;
        case 3: { bool _r = _t->lookupJob((*reinterpret_cast< BatchId(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 4: _t->handleSubmissionReply((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< uint(*)>(_a[2]))); break;
        case 5: _t->handleJobStateChange((*reinterpret_cast< uint(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        case 6: _t->handleLookupJobReply((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const QJsonObject(*)>(_a[2]))); break;
        case 7: _t->handleErrorResponse((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3])),(*reinterpret_cast< const QJsonValue(*)>(_a[4]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (BatchJob::*)(Avogadro::MoleQueue::BatchJob::BatchId , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BatchJob::jobUpdated)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (BatchJob::*)(Avogadro::MoleQueue::BatchJob::BatchId , Avogadro::MoleQueue::BatchJob::JobState );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&BatchJob::jobCompleted)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::MoleQueue::BatchJob::staticMetaObject = { {
    QMetaObject::SuperData::link<QObject::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__MoleQueue__BatchJob.data,
    qt_meta_data_Avogadro__MoleQueue__BatchJob,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::MoleQueue::BatchJob::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::MoleQueue::BatchJob::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__MoleQueue__BatchJob.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int Avogadro::MoleQueue::BatchJob::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 8;
    }
    return _id;
}

// SIGNAL 0
void Avogadro::MoleQueue::BatchJob::jobUpdated(Avogadro::MoleQueue::BatchJob::BatchId _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::MoleQueue::BatchJob::jobCompleted(Avogadro::MoleQueue::BatchJob::BatchId _t1, Avogadro::MoleQueue::BatchJob::JobState _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

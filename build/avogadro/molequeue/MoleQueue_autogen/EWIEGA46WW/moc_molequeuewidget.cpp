/****************************************************************************
** Meta object code from reading C++ file 'molequeuewidget.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.17)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../../../avogadro/molequeue/molequeuewidget.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'molequeuewidget.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.17. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget_t {
    QByteArrayData data[24];
    char stringdata0[308];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget_t qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget = {
    {
QT_MOC_LITERAL(0, 0, 36), // "Avogadro::MoleQueue::MoleQueu..."
QT_MOC_LITERAL(1, 37, 12), // "jobSubmitted"
QT_MOC_LITERAL(2, 50, 0), // ""
QT_MOC_LITERAL(3, 51, 7), // "success"
QT_MOC_LITERAL(4, 59, 11), // "jobFinished"
QT_MOC_LITERAL(5, 71, 10), // "jobUpdated"
QT_MOC_LITERAL(6, 82, 9), // "JobObject"
QT_MOC_LITERAL(7, 92, 3), // "job"
QT_MOC_LITERAL(8, 96, 14), // "setJobTemplate"
QT_MOC_LITERAL(9, 111, 15), // "refreshPrograms"
QT_MOC_LITERAL(10, 127, 16), // "submitJobRequest"
QT_MOC_LITERAL(11, 144, 27), // "showAndSelectProgramHandler"
QT_MOC_LITERAL(12, 172, 16), // "onLookupJobReply"
QT_MOC_LITERAL(13, 189, 5), // "reqId"
QT_MOC_LITERAL(14, 195, 6), // "result"
QT_MOC_LITERAL(15, 202, 19), // "onSubmissionSuccess"
QT_MOC_LITERAL(16, 222, 7), // "localId"
QT_MOC_LITERAL(17, 230, 11), // "moleQueueId"
QT_MOC_LITERAL(18, 242, 19), // "onSubmissionFailure"
QT_MOC_LITERAL(19, 262, 5), // "error"
QT_MOC_LITERAL(20, 268, 16), // "onJobStateChange"
QT_MOC_LITERAL(21, 285, 4), // "mqId"
QT_MOC_LITERAL(22, 290, 8), // "oldState"
QT_MOC_LITERAL(23, 299, 8) // "newState"

    },
    "Avogadro::MoleQueue::MoleQueueWidget\0"
    "jobSubmitted\0\0success\0jobFinished\0"
    "jobUpdated\0JobObject\0job\0setJobTemplate\0"
    "refreshPrograms\0submitJobRequest\0"
    "showAndSelectProgramHandler\0"
    "onLookupJobReply\0reqId\0result\0"
    "onSubmissionSuccess\0localId\0moleQueueId\0"
    "onSubmissionFailure\0error\0onJobStateChange\0"
    "mqId\0oldState\0newState"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Avogadro__MoleQueue__MoleQueueWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x06 /* Public */,
       4,    1,   72,    2, 0x06 /* Public */,
       5,    1,   75,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    1,   78,    2, 0x0a /* Public */,
       9,    0,   81,    2, 0x0a /* Public */,
      10,    0,   82,    2, 0x0a /* Public */,
      11,    0,   83,    2, 0x08 /* Private */,
      12,    2,   84,    2, 0x08 /* Private */,
      15,    2,   89,    2, 0x08 /* Private */,
      18,    3,   94,    2, 0x08 /* Private */,
      20,    3,  101,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, 0x80000000 | 6,    7,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Int,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, QMetaType::QJsonObject,   13,   14,
    QMetaType::Void, QMetaType::Int, QMetaType::UInt,   16,   17,
    QMetaType::Void, QMetaType::Int, QMetaType::UInt, QMetaType::QString,   16,    2,   19,
    QMetaType::Void, QMetaType::UInt, QMetaType::QString, QMetaType::QString,   21,   22,   23,

       0        // eod
};

void Avogadro::MoleQueue::MoleQueueWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MoleQueueWidget *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->jobSubmitted((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 1: _t->jobFinished((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 2: _t->jobUpdated((*reinterpret_cast< const JobObject(*)>(_a[1]))); break;
        case 3: _t->setJobTemplate((*reinterpret_cast< const JobObject(*)>(_a[1]))); break;
        case 4: _t->refreshPrograms(); break;
        case 5: { int _r = _t->submitJobRequest();
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 6: _t->showAndSelectProgramHandler(); break;
        case 7: _t->onLookupJobReply((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< const QJsonObject(*)>(_a[2]))); break;
        case 8: _t->onSubmissionSuccess((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< uint(*)>(_a[2]))); break;
        case 9: _t->onSubmissionFailure((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< uint(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        case 10: _t->onJobStateChange((*reinterpret_cast< uint(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< const QString(*)>(_a[3]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (MoleQueueWidget::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&MoleQueueWidget::jobSubmitted)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (MoleQueueWidget::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&MoleQueueWidget::jobFinished)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (MoleQueueWidget::*)(const JobObject & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&MoleQueueWidget::jobUpdated)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject Avogadro::MoleQueue::MoleQueueWidget::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget.data,
    qt_meta_data_Avogadro__MoleQueue__MoleQueueWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *Avogadro::MoleQueue::MoleQueueWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Avogadro::MoleQueue::MoleQueueWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Avogadro__MoleQueue__MoleQueueWidget.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int Avogadro::MoleQueue::MoleQueueWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
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
void Avogadro::MoleQueue::MoleQueueWidget::jobSubmitted(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Avogadro::MoleQueue::MoleQueueWidget::jobFinished(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void Avogadro::MoleQueue::MoleQueueWidget::jobUpdated(const JobObject & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

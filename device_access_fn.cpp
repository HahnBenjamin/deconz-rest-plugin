/*
 * Copyright (c) 2021 dresden elektronik ingenieurtechnik gmbh.
 * All rights reserved.
 *
 * The software in this package is published under the terms of the BSD
 * style license a copy of which has been included with this distribution in
 * the LICENSE.txt file.
 *
 */

#include "air_quality.h"
#include "device_access_fn.h"
#include "device_js/device_js.h"
#include "ias_zone.h"
#include "resource.h"
#include "zcl/zcl.h"
#include "tuya.h"
#include "de_web_plugin_private.h"

enum DP_Types : quint8
{
    raw = 0x00, // epresents a DP of raw data type (nBytes)
    boolean = 0x01,
    value = 0x02,    // represents a DP of integer data type, in big-endian format (4 bytes)
    t_string = 0x03, // sting (nbytes)
    t_enum = 0x04,   // Represents a DP of enum data type, ranging from 0 to 255.
    bitmap = 0x05    // Represents a DP of fault data type. Data greater than one byte is transmitted in big-endian format. 1, 2, or 4 bytes
};

enum DA_Constants
{
    BroadcastEndpoint = 255, //! Accept incoming commands from any endpoint.
    AutoEndpoint = 0         //! Use src/dst endpoint of the related Resource (uniqueid).
};

struct ParseFunction
{
    ParseFunction(const QString &_name, const int _arity, ParseFunction_t _fn) : name(_name),
                                                                                 arity(_arity),
                                                                                 fn(_fn)
    {
    }
    QString name;
    int arity = 0; // number of parameters given by the device description file
    ParseFunction_t fn = nullptr;
};

struct ReadFunction
{
    ReadFunction(const QString &_name, const int _arity, ReadFunction_t _fn) : name(_name),
                                                                               arity(_arity),
                                                                               fn(_fn)
    {
    }
    QString name;
    int arity = 0; // number of parameters given by the device description file
    ReadFunction_t fn = nullptr;
};

struct WriteFunction
{
    WriteFunction(const QString &_name, const int _arity, WriteFunction_t _fn) : name(_name),
                                                                                 arity(_arity),
                                                                                 fn(_fn)
    {
    }
    QString name;
    int arity = 0; // number of parameters given by the device description file
    WriteFunction_t fn = nullptr;
};

quint8 zclNextSequenceNumber(); // todo defined in de_web_plugin_private.h

/*! Helper to get an unsigned int from \p var which might be a number or string value.

   \param var - Holds the string or number.
   \param max – Upper bound of the allowed value.
   \param ok – true if var holds and uint which is <= \p max.
 */
uint variantToUint(const QVariant &var, size_t max, bool *ok)
{
    Q_ASSERT(ok);
    *ok = false;

    if (var.isNull())
    {
        return 0;
    }

    const auto val = var.toString().toUInt(ok, 0);
    *ok = *ok && val <= max;

    return *ok ? val : 0;
}

/*! Extracts common ZCL parameters from an object.
 */
static ZCL_Param getZclParam(const QVariantMap &param)
{
    ZCL_Param result{};

    if (!param.contains(QLatin1String("cl")))
    {
        return result;
    }

    bool ok = true;

    result.endpoint = param.contains("ep") ? variantToUint(param["ep"], UINT8_MAX, &ok) : quint8(AutoEndpoint);
    result.clusterId = ok ? variantToUint(param["cl"], UINT16_MAX, &ok) : 0;
    result.manufacturerCode = ok && param.contains("mf") ? variantToUint(param["mf"], UINT16_MAX, &ok) : 0;

    if (param.contains(QLatin1String("cmd"))) // optional
    {
        result.commandId = variantToUint(param["cmd"], UINT8_MAX, &ok);
        result.hasCommandId = ok ? 1 : 0;
    }
    else
    {
        result.hasCommandId = 0;
    }

    result.attributeCount = 0;
    const auto attr = param[QLatin1String("at")]; // optional

    if (!ok)
    {
    }
    else if (attr.type() == QVariant::String)
    {
        result.attributes[result.attributeCount] = variantToUint(attr, UINT16_MAX, &ok);
        result.attributeCount = 1;
    }
    else if (attr.type() == QVariant::List)
    {
        const auto arr = attr.toList();
        for (const auto &at : arr)
        {
            if (result.attributeCount == ZCL_Param::MaxAttributes)
            {
                break;
            }

            if (ok && at.type() == QVariant::String)
            {
                result.attributes[result.attributeCount] = variantToUint(at, UINT16_MAX, &ok);
                result.attributeCount++;
            }
        }

        ok = result.attributeCount == size_t(arr.size());
    }
    else if (param["eval"].toString().contains("Attr")) // guard against missing "at"
    {
        ok = false;
    }

    result.valid = ok;

    return result;
}

quint8 resolveAutoEndpoint(const Resource *r)
{
    quint8 result = AutoEndpoint;

    // hack to get endpoint. todo find better solution
    const auto ls = r->item(RAttrUniqueId)->toString().split('-', SKIP_EMPTY_PARTS);
    if (ls.size() >= 2)
    {
        bool ok = false;
        uint ep = ls[1].toUInt(&ok, 16);
        if (ok && ep < BroadcastEndpoint)
        {
            result = ep;
        }
    }

    return result;
}

/*! Evaluates an items Javascript expression for a received attribute.
 */
bool evalZclAttribute(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const deCONZ::ZclAttribute &attr, const QVariant &parseParameters)
{
    bool ok = false;
    const auto &zclParam = item->zclParam();

    for (size_t i = 0; i < zclParam.attributeCount; i++)
    {
        if (zclParam.attributes[i] == attr.id())
        {
            ok = true;
            break;
        }
    }

    if (!ok)
    {
        return false;
    }

    const auto expr = parseParameters.toMap()["eval"].toString();

    if (!expr.isEmpty())
    {
        DeviceJs engine;
        engine.setResource(r);
        engine.setItem(item);
        engine.setZclAttribute(attr);
        engine.setZclFrame(zclFrame);
        engine.setApsIndication(ind);

        if (engine.evaluate(expr) == JsEvalResult::Ok)
        {
            const auto res = engine.result();
            if (res.isValid())
            {
                DBG_Printf(DBG_DDF, "%s/%s expression: %s --> %s\n", r->item(RAttrUniqueId)->toCString(), item->descriptor().suffix, qPrintable(expr), qPrintable(res.toString()));

                // item->setValue(res, ResourceItem::SourceDevice);
                return true;
            }
        }
        else
        {
            DBG_Printf(DBG_DDF, "failed to evaluate expression for %s/%s: %s, err: %s\n", r->item(RAttrUniqueId)->toCString(), item->descriptor().suffix, qPrintable(expr), qPrintable(engine.errorString()));
        }
    }
    return false;
}

/*! Evaluates an items Javascript expression for a received ZCL frame.
 */
bool evalZclFrame(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    const auto expr = parseParameters.toMap()["eval"].toString();

    if (!expr.isEmpty())
    {
        DeviceJs engine;
        engine.setResource(r);
        engine.setItem(item);
        engine.setZclFrame(zclFrame);
        engine.setApsIndication(ind);

        if (engine.evaluate(expr) == JsEvalResult::Ok)
        {
            const auto res = engine.result();
            if (res.isValid())
            {
                DBG_Printf(DBG_INFO, "expression: %s --> %s\n", qPrintable(expr), qPrintable(res.toString()));
                return true;
            }
        }
        else
        {
            DBG_Printf(DBG_INFO, "failed to evaluate expression for %s/%s: %s, err: %s\n", qPrintable(r->item(RAttrUniqueId)->toString()), item->descriptor().suffix, qPrintable(expr), qPrintable(engine.errorString()));
        }
    }
    return false;
}

/*! A general purpose function to map number values of a source item to a string which is stored in \p item .

    The item->parseParameters() is expected to be an object (given in the device description file).
    {"fn": "numtostring", "srcitem": suffix, "op": operator, "to": array}
    - srcitem: the suffix of the source item which holds the numeric value
    - op: (lt | le | eq | gt | ge) the operator used to match the 'to' array
    - to: [number, string, [number, string], ...] an sorted array to map 'number -> string' with the given operator

    Example: { "parse": {"fn": "numtostr", "srcitem": "state/airqualityppb", "op": "le", "to": [65, "good", 65535, "bad"] }
 */
bool parseNumericToString(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    Q_UNUSED(ind)
    Q_UNUSED(zclFrame)
    bool result = false;

    ResourceItem *srcItem = nullptr;
    const auto map = parseParameters.toMap();

    enum Op
    {
        OpNone,
        OpLessThan,
        OpLessEqual,
        OpEqual,
        OpGreaterThan,
        OpGreaterEqual
    };
    Op op = OpNone;

    if (!item->parseFunction()) // init on first call
    {
        if (item->descriptor().type != DataTypeString)
        {
            return result;
        }

        if (!map.contains(QLatin1String("to")) || !map.contains(QLatin1String("op")) || !map.contains(QLatin1String("srcitem")))
        {
            return result;
        }

        item->setParseFunction(parseNumericToString);
    }

    ResourceItemDescriptor rid;
    if (!getResourceItemDescriptor(map["srcitem"].toString(), rid))
    {
        return result;
    }

    srcItem = r->item(rid.suffix);
    if (!srcItem)
    {
        return result;
    }

    if (!(srcItem->needPushChange() || srcItem->needPushSet()))
    {
        return result; // only update if needed
    }

    {
        const auto opString = map[QLatin1String("op")].toString();

        if (opString == QLatin1String("le"))
        {
            op = OpLessEqual;
        }
        else if (opString == QLatin1String("lt"))
        {
            op = OpLessThan;
        }
        else if (opString == QLatin1String("eq"))
        {
            op = OpEqual;
        }
        else if (opString == QLatin1String("ge"))
        {
            op = OpGreaterEqual;
        }
        else if (opString == QLatin1String("gt"))
        {
            op = OpGreaterThan;
        }
        else
        {
            return result;
        }
    }

    const qint64 num = srcItem->toNumber();
    const auto to = map["to"].toList();

    if (to.size() & 1)
    {
        return result; // array size must be even
    }

    auto i = std::find_if(to.cbegin(), to.cend(), [num, op](const QVariant &var)
                          {
        if (var.type() == QVariant::Double)
        {
            if (op == OpLessEqual)    { return num <= var.toInt(); }
            if (op == OpLessThan)     { return num < var.toInt();  }
            if (op == OpEqual)        { return num == var.toInt(); }
            if (op == OpGreaterEqual) { return num >= var.toInt(); }
            if (op == OpGreaterThan)  { return num > var.toInt();  }
        }
        return false; });

    if (i != to.cend())
    {
        i++; // point next element (string)

        if (i != to.cend() && i->type() == QVariant::String)
        {
            const QString str = i->toString();
            if (!str.isEmpty())
            {
                item->setValue(str);
                item->setLastZclReport(srcItem->lastZclReport()); // Treat as report
                result = true;
            }
        }
    }

    return result;
}

/*! A generic function to parse ZCL values from read/report commands.
    The item->parseParameters() is expected to be an object (given in the device description file).

    {"fn": "zcl", "ep": endpoint, "cl": clusterId, "at": attributeId, "mf": manufacturerCode, "eval": expression}

    - endpoint: (optional) 255 means any endpoint, 0 means auto selected from the related resource, defaults to 0
    - clusterId: string hex value
    - attributeId: string hex value or array of string hex values
    - manufacturerCode: (optional) string hex value, defaults to "0x0000" for non manufacturer specific commands
    - expression: Javascript expression to transform the raw value

    Example: { "parse": {"fn": "zcl", "ep:" 1, "cl": "0x0402", "at": "0x0000", "eval": "Attr.val + R.item('config/offset').val" } }
 */
bool parseZclAttribute(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    bool result = false;

    if (!item->parseFunction()) // init on first call
    {
        Q_ASSERT(!parseParameters.isNull());
        if (parseParameters.isNull())
        {
            return result;
        }

        ZCL_Param param = getZclParam(parseParameters.toMap());

        Q_ASSERT(param.valid);
        if (!param.valid)
        {
            return result;
        }

        if (param.hasCommandId && param.commandId != zclFrame.commandId())
        {
            return result;
        }
        else if (!param.hasCommandId && zclFrame.commandId() != deCONZ::ZclReadAttributesResponseId && zclFrame.commandId() != deCONZ::ZclReportAttributesId)
        {
            return result;
        }

        if (param.manufacturerCode != zclFrame.manufacturerCode())
        {
            return result;
        }

        if (param.endpoint == AutoEndpoint)
        {
            param.endpoint = resolveAutoEndpoint(r);

            if (param.endpoint == AutoEndpoint)
            {
                return result;
            }
        }

        item->setParseFunction(parseZclAttribute);
        item->setZclProperties(param);
    }

    const auto &zclParam = item->zclParam();

    if (ind.clusterId() != zclParam.clusterId)
    {
        return result;
    }

    if (zclParam.endpoint < BroadcastEndpoint && zclParam.endpoint != ind.srcEndpoint())
    {
        return result;
    }

    if (zclParam.attributeCount == 0) // attributes are optional
    {
        if (evalZclFrame(r, item, ind, zclFrame, parseParameters))
        {
            result = true;
        }
        return result;
    }

    if (zclFrame.payload().isEmpty() && zclParam.attributeCount > 0)
    {
        return result;
    }

    QDataStream stream(zclFrame.payload());
    stream.setByteOrder(QDataStream::LittleEndian);

    while (!stream.atEnd())
    {
        quint16 attrId;
        quint8 status;
        quint8 dataType;

        stream >> attrId;

        if (zclFrame.commandId() == deCONZ::ZclReadAttributesResponseId)
        {
            stream >> status;
            if (status != deCONZ::ZclSuccessStatus)
            {
                continue;
            }
        }

        stream >> dataType;
        deCONZ::ZclAttribute attr(attrId, dataType, QLatin1String(""), deCONZ::ZclReadWrite, true);

        if (!attr.readFromStream(stream))
        {
            break;
        }

        if (evalZclAttribute(r, item, ind, zclFrame, attr, parseParameters))
        {
            if (zclFrame.commandId() == deCONZ::ZclReportAttributesId)
            {
                item->setLastZclReport(deCONZ::steadyTimeRef().ref);
            }
            result = true;
        }
    }

    return result;
}

/*! Extracts manufacturer specific Xiaomi ZCL attribute from report commands to basic cluster.

    \param zclFrame - Contains the special report with attribute 0xff01, 0xff02 or 0x00f7.
    \param rtag - The tag or struct index of the attribute to return.
    \returns Parsed attribute, use attr.id() != 0xffff to check for valid result.
 */
deCONZ::ZclAttribute parseXiaomiZclTag(const quint8 rtag, const deCONZ::ZclFrame &zclFrame)
{
    deCONZ::ZclAttribute result;

    quint16 attrId = 0;
    quint8 dataType = 0;
    quint8 length = 0;

    QDataStream stream(zclFrame.payload());
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setFloatingPointPrecision(QDataStream::SinglePrecision);

    while (attrId == 0 && !stream.atEnd())
    {
        quint16 a;
        stream >> a;
        stream >> dataType;

        if (dataType == deCONZ::ZclCharacterString || dataType == deCONZ::ZclOctedString)
        {
            stream >> length;
        }

        if (a == 0xff01 && dataType == deCONZ::ZclCharacterString)
        {
            attrId = a;
        }
        else if (a == 0xff02 && dataType == 0x4c /*deCONZ::ZclStruct*/)
        {
            //            attrId = a;
        }
        else if (a == 0x00f7 && dataType == deCONZ::ZclOctedString)
        {
            attrId = a;
        }

        if (dataType == deCONZ::ZclCharacterString && attrId != 0xff01)
        {
            for (; length > 0; length--) // skip string attribute
            {
                quint8 dummy;
                stream >> dummy;
            }
        }
    }

    if (stream.atEnd() || attrId == 0)
    {
        return result;
    }

    while (!stream.atEnd())
    {
        quint8 tag = 0;

        if (attrId == 0xff01 || attrId == 0x00f7)
        {
            stream >> tag;
        }

        stream >> dataType;

        deCONZ::ZclAttribute atmp(tag, dataType, QLatin1String(""), deCONZ::ZclRead, true);

        if (!atmp.readFromStream(stream))
        {
            return result;
        }

        if (tag == rtag)
        {
            result = atmp;
            break;
        }
    }

    return result;
}

bool parseTuyaSpecial(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    bool result = false;

    if (zclFrame.isDefaultResponse())
    {
        return false;
    }

    DBG_Printf(DBG_INFO_L2, "Tuya debug Request : Address 0x%016llX, Endpoint 0x%02X, Command 0x%02X, Payload %s\n", ind.srcAddress().ext(), ind.srcEndpoint(), zclFrame.commandId(), qPrintable(zclFrame.payload().toHex()));

    if (zclFrame.commandId() == TUYA_REQUEST)
    {
        // 0x00 : TUYA_REQUEST > Used to send command, so not used here
        return false;
    }
    else if (zclFrame.commandId() == TUYA_REPORTING || zclFrame.commandId() == TUYA_QUERY || zclFrame.commandId() == TUYA_STATUS_SEARCH)
    {
        // 0x01 : TUYA_REPORTING > Used to inform of changes in its state.
        // 0x02 : TUYA_QUERY > Send after receiving a 0x00 command.
        // 0x06 : TUYA_STATUS_SEARCH > kind of reporting.

        if (zclFrame.payload().size() < 7)
        {
            DBG_Printf(DBG_INFO, "Tuya : Payload too short\n");
            return false;
        }

        DBG_Printf(DBG_INFO, "Tuya : Payload size %d\n", zclFrame.payload().size());

        const auto map = parseParameters.toMap();

        bool ok;
        const auto datapointId = variantToUint(map.value("dpid"), UINT8_MAX, &ok);

        QDataStream stream(zclFrame.payload());
        stream.setByteOrder(QDataStream::BigEndian);

        // "dp" field describes the action/message of a command frame and was composed by a type and an identifier
        // Composed by a type (dp_type) and an identifier (dp_identifier), the identifier is device dependant.
        // "transid" is just a "counter", a response will have the same transif than the command.
        // "Status" and "fn" are always 0
        // More explanations at top of file

        if (!item->parseFunction())
        {
        }

        quint16 sequenceNumber;

        quint8 dp_id;
        quint8 dp_type;
        quint16 length;
        quint8 *dataBuf;
        deCONZ::ZclAttribute attribute;

        stream >> sequenceNumber;
        bool match = false;
        while (!match && !stream.atEnd())
        {

            stream >> dp_id;
            stream >> dp_type;

            stream >> length;
            dataBuf = new quint8[length];

            DBG_Printf(DBG_INFO, "Tuya debug data length %u (0x%02X)\n", length, length);

            for (int i = 0; i < length; i++)
            {
                stream >> dataBuf[i];
            }

            DBG_Printf(DBG_INFO, "Tuya debug 4 : Address 0x%016llX Payload %s\n", ind.srcAddress().ext(), qPrintable(zclFrame.payload().toHex()));
            DBG_Printf(DBG_INFO, "Tuya debug 5 : sequence: %u dp_id: %u dp_type: %u length: %u Data %d\n", sequenceNumber, dp_id, dp_type, length, dataBuf);

            if (datapointId != dp_id)
            {
                continue;
            }
            match = true;
            break;
        };

        if (!match)
        {
            return false;
        }

        switch (dp_type)
        {
        case DP_TYPE_RAW:{
            //TO DO
            break;
        }
        case DP_TYPE_VALUE:
        {
            int value = int((unsigned char)(dataBuf[0]) << 24 |
                            (unsigned char)(dataBuf[1]) << 16 |
                            (unsigned char)(dataBuf[2]) << 8 |
                            (unsigned char)(dataBuf[3]));
            DBG_Printf(DBG_INFO, "##### Tuya debug DP:, %u value %i\n", dp_id, value);
            attribute.setDataType(deCONZ::Zcl32BitInt);
            attribute.setValue((qint64)value);
            break;
        }
        case DP_TYPE_ENUM:
        {
            DBG_Printf(DBG_INFO, "##### Tuya debug DP: %u enum  value %u\n", dp_id, dataBuf[0]);
            attribute.setDataType(deCONZ::Zcl8BitEnum);
            attribute.setEnumerationId(dataBuf[0]);
            break;
        }
        case DP_TYPE_BOOL:
        {
            DBG_Printf(DBG_INFO, "##### Tuya debug DP: %u bool %s\n", dp_id, dataBuf[0] ? "true" : "false");
            attribute.setDataType(deCONZ::ZclBoolean);
            attribute.setValue((dataBuf[0] == 0x01) ? true : false);

            break;
        }
        case DP_TYPE_STRING:
        {
            char str[((int)length) + 1];
            // Copy contents
            memcpy(str, dataBuf, length);
            // Append NULL terminator
            str[((int)length)] = '\0';
            DBG_Printf(DBG_INFO, "##### Tuya debug DP: %u string value %s\n", dp_id, str);
            attribute.setDataType(deCONZ::ZclCharacterString);
            attribute.setValue((dataBuf[0] == 0x01) ? true : false);
            break;
        }
        // Bitmap
        case DP_TYPE_FAULT: 
        {
            quint64 value;
            switch (length) {
                case 1:
        {
            attribute.setDataType(deCONZ::Zcl8BitBitMap);
                    value = quint64(dataBuf[0]);
        break;
        }
        case 2:
        {
            attribute.setDataType(deCONZ::Zcl16BitBitMap);
            value = quint64((unsigned char)(dataBuf[0]) << 8 | (unsigned char)(dataBuf[1]));
            break;
        }
        case 4:
        {
            attribute.setDataType(deCONZ::Zcl32BitBitMap);
            value = quint64((unsigned char)(dataBuf[0]) << 24 |
                            (unsigned char)(dataBuf[1]) << 16 |
                            (unsigned char)(dataBuf[2]) << 8 |
                            (unsigned char)(dataBuf[3]));
                            break;
        }
 

        default:
            break;
        }

    }
default:
    break;
}

const auto expr = map.value("eval").toString();
if (!ok || expr.isEmpty())
{
    return result;
}

if (!expr.isEmpty())
{
    DeviceJs engine;
    engine.setResource(r);
    engine.setItem(item);
    engine.setZclAttribute(attribute);

    if (engine.evaluate(expr) == JsEvalResult::Ok)
    {
        const auto res = engine.result();
        DBG_Printf(DBG_INFO, "expression: %s --> %s\n", qPrintable(expr), qPrintable(res.toString()));
        // attribute.setValue(res);
        return true;
    }
    else
    {
        DBG_Printf(DBG_INFO, "failed to evaluate expression for %s/%s: %s, err: %s\n", qPrintable(r->item(RAttrUniqueId)->toString()), item->descriptor().suffix, qPrintable(expr), qPrintable(engine.errorString()));
        return result;
    }
}
}
else if (zclFrame.commandId() == TUYA_TIME_SYNCHRONISATION)
{
    DBG_Printf(DBG_INFO, "Tuya debug 1 : Time sync request\n");

    QDataStream stream(zclFrame.payload());
    stream.setByteOrder(QDataStream::BigEndian);

    quint16 sequenceNumber;
    stream >> sequenceNumber;

    /* ZCL Payload also contains the Time on the deivce but this is not of interest in this case

    quint32 standardTimeStamp;
    stream >> standardTimeStamp;

    quint32 localTimeStamp;
    stream >> localTimeStamp;
    */

    quint32 timeNow = 0xFFFFFFFF;       // id 0x0000 Time
    qint32 timeZone = 0xFFFFFFFF;       // id 0x0002 TimeZone
    quint32 timeDstStart = 0xFFFFFFFF;  // id 0x0003 DstStart
    quint32 timeDstEnd = 0xFFFFFFFF;    // id 0x0004 DstEnd
    qint32 timeDstShift = 0xFFFFFFFF;   // id 0x0005 DstShift
    quint32 timeStdTime = 0xFFFFFFFF;   // id 0x0006 StandardTime
    quint32 timeLocalTime = 0xFFFFFFFF; // id 0x0007 LocalTime

    getTime(&timeNow, &timeZone, &timeDstStart, &timeDstEnd, &timeDstShift, &timeStdTime, &timeLocalTime, UNIX_EPOCH);

    QByteArray data;
    QDataStream stream2(&data, QIODevice::WriteOnly);
    stream2.setByteOrder(QDataStream::BigEndian);

    stream2 << sequenceNumber;

    // stream2.setByteOrder(QDataStream::BigEndian);

    // Add UTC time
    stream2 << timeNow;
    // Add local time
    stream2 << timeLocalTime;

    DeRestPluginPrivate *app = DeRestPluginPrivate::instance();
    app->sendTuyaCommand(ind, TUYA_TIME_SYNCHRONISATION, data);

    return true;
}
return result;
}

/*! A generic function to parse ZCL values from Xiaomi special report commands.
    The item->parseParameters() is expected to be an object (given in the device description file).

    {"fn": "xiaomi:special", "ep": endpoint, "at": attributeId, "idx": index, "eval": expression}

    - endpoint: (optional), 0xff means any endpoint (default: 0xff)
    - attributeId: string hex value of 0xff01, 0xff02 or 0x00f7.
    - index: string hex value representing the tag or index in the structure
    - expression: Javascript expression to transform the raw value (as alternative "script" can be used to reference a external JS script file)

    Example: { "parse": {"fn": "xiaomi:special", "at": "0xff01", "idx": "0x01", "eval": "Item.val = Attr.val" } }
 */
bool parseXiaomiSpecial(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    bool result = false;

    if (zclFrame.commandId() != deCONZ::ZclReportAttributesId)
    {
        return result;
    }

    if (ind.clusterId() != 0x0000 && ind.clusterId() != 0xfcc0) // must be basic or lumi specific cluster
    {
        return result;
    }

    if (!item->parseFunction()) // init on first call
    {
        Q_ASSERT(!parseParameters.isNull());
        if (parseParameters.isNull())
        {
            return result;
        }

        const auto map = parseParameters.toMap();

        bool ok = true;
        ZCL_Param param;

        param.endpoint = BroadcastEndpoint; // default
        param.clusterId = 0x0000;

        if (ind.clusterId() == 0xfcc0)
        {
            param.clusterId = 0xfcc0;
            param.manufacturerCode = 0x115f;
        }

        if (map.contains(QLatin1String("ep")))
        {
            param.endpoint = variantToUint(map["ep"], UINT8_MAX, &ok);
        }
        const auto at = ok ? variantToUint(map["at"], UINT16_MAX, &ok) : 0;
        const auto idx = ok ? variantToUint(map["idx"], UINT16_MAX, &ok) : 0;

        DBG_Assert(at == 0xff01 || at == 0xff02 || at == 0x00f7);
        if (!ok)
        {
            return result;
        }

        param.attributeCount = 2;
        param.attributes[0] = at;
        // keep tag/idx as second "attribute id"
        param.attributes[1] = idx;

        if (param.endpoint == AutoEndpoint)
        {
            param.endpoint = resolveAutoEndpoint(r);

            if (param.endpoint == AutoEndpoint)
            {
                return result;
            }
        }

        item->setParseFunction(parseXiaomiSpecial);
        item->setZclProperties(param);
    }

    const auto &zclParam = item->zclParam();

    if (!(ind.clusterId() == 0x0000 || ind.clusterId() == 0xfcc0) || zclFrame.payload().isEmpty())
    {
        return result;
    }

    if (zclParam.endpoint < BroadcastEndpoint && zclParam.endpoint != ind.srcEndpoint())
    {
        return result;
    }

    Q_ASSERT(zclParam.attributeCount == 2); // attribute id + tag/idx
    const auto attr = parseXiaomiZclTag(zclParam.attributes[1], zclFrame);

    if (evalZclAttribute(r, item, ind, zclFrame, attr, parseParameters))
    {
        result = true;
    }

    return result;
}

/*! A function to parse IAS Zone status change notifications or read/report commands for IAS Zone status of the IAS Zone cluster.
    The item->parseParameters() is expected to be an object (given in the device description file).

    {"fn": "ias:zonestatus", "mask": expression}

    - mask (optional): The bitmask to be applied for Alarm1 and Alarm2 of the IAS zone status value as list of strings

    Example: { "parse": {"fn": "ias:zonestatus", "mask": "alarm1,alarm2" } }
 */
bool parseIasZoneNotificationAndStatus(Resource *r, ResourceItem *item, const deCONZ::ApsDataIndication &ind, const deCONZ::ZclFrame &zclFrame, const QVariant &parseParameters)
{
    bool result = false;

    if (ind.clusterId() != IAS_ZONE_CLUSTER_ID)
    {
        return result;
    }

    if (ind.srcEndpoint() != resolveAutoEndpoint(r))
    {
        return result;
    }

    if (zclFrame.isClusterCommand()) // is IAS Zone status notification?
    {
        if (zclFrame.commandId() != CMD_STATUS_CHANGE_NOTIFICATION)
        {
            return result;
        }
    }
    else if (zclFrame.commandId() != deCONZ::ZclReadAttributesResponseId && zclFrame.commandId() != deCONZ::ZclReportAttributesId) // is read or report?
    {
        return result;
    }

    if (!item->parseFunction()) // init on first call
    {
        item->setParseFunction(parseIasZoneNotificationAndStatus);
    }

    QDataStream stream(zclFrame.payload());
    stream.setByteOrder(QDataStream::LittleEndian);

    quint16 zoneStatus = UINT16_MAX;

    while (!stream.atEnd())
    {
        if (zclFrame.isClusterCommand())
        {
            quint8 extendedStatus;
            quint8 zoneId;
            quint16 delay;

            stream >> zoneStatus;
            stream >> extendedStatus; // reserved, set to 0
            stream >> zoneId;
            stream >> delay;

            DBG_Assert(stream.status() == QDataStream::Ok);
        }
        else
        {
            quint16 attrId;
            quint8 status;
            quint8 dataType;

            stream >> attrId;

            if (zclFrame.commandId() == deCONZ::ZclReadAttributesResponseId)
            {
                stream >> status;
                if (status != deCONZ::ZclSuccessStatus)
                {
                    continue;
                }
            }

            stream >> dataType;
            deCONZ::ZclAttribute attr(attrId, dataType, QLatin1String(""), deCONZ::ZclReadWrite, true);

            if (!attr.readFromStream(stream))
            {
                break;
            }

            if (attr.id() == 0x0002)
            {
                zoneStatus = attr.numericValue().u16;
                break;
            }
        }
    }

    if (zoneStatus != UINT16_MAX)
    {
        int mask = 0;
        const char *suffix = item->descriptor().suffix;

        if (suffix == RStateAlarm || suffix == RStateCarbonMonoxide || suffix == RStateFire || suffix == RStateOpen ||
            suffix == RStatePresence || suffix == RStateVibration || suffix == RStateWater)
        {
            const auto map = parseParameters.toMap();

            if (map.contains(QLatin1String("mask")))
            {
                QStringList alarmMask = map["mask"].toString().split(',', QString::SkipEmptyParts);

                if (alarmMask.contains(QLatin1String("alarm1")))
                {
                    mask |= STATUS_ALARM1;
                }
                if (alarmMask.contains(QLatin1String("alarm2")))
                {
                    mask |= STATUS_ALARM2;
                }
            }
        }
        else if (suffix == RStateTampered)
        {
            mask |= STATUS_TAMPER;
        }
        else if (suffix == RStateLowBattery)
        {
            mask |= STATUS_BATTERY;
        }
        else if (suffix == RStateTest)
        {
            mask |= STATUS_TEST;
        }

        item->setValue((zoneStatus & mask) != 0);
        item->setLastZclReport(deCONZ::steadyTimeRef().ref); // Treat as report
        result = true;
    }

    return result;
}

/*! A generic function to read ZCL attributes.
    The item->readParameters() is expected to be an object (given in the device description file).

    { "fn": "zcl", "ep": endpoint, "cl" : clusterId, "at": attributeId, "mf": manufacturerCode }

    - endpoint, 0xff means any endpoint
    - clusterId: string hex value
    - attributeId: string hex value
    - manufacturerCode: (optional) string hex value, defaults to "0x0000" for non manufacturer specific commands

    Example: { "read": {"fn": "zcl", "ep": 1, "cl": "0x0402", "at": "0x0000", "mf": "0x110b"} }
 */
static DA_ReadResult readZclAttribute(const Resource *r, const ResourceItem *item, deCONZ::ApsController *apsCtrl, const QVariant &readParameters)
{
    Q_UNUSED(item)

    DA_ReadResult result;

    Q_ASSERT(!readParameters.isNull());
    if (readParameters.isNull())
    {
        return result;
    }

    auto *rTop = r->parentResource() ? r->parentResource() : r;

    const auto *extAddr = rTop->item(RAttrExtAddress);
    const auto *nwkAddr = rTop->item(RAttrNwkAddress);

    if (!extAddr || !nwkAddr)
    {
        return result;
    }

    auto param = getZclParam(readParameters.toMap());

    if (!param.valid)
    {
        return result;
    }

    if (param.endpoint == AutoEndpoint)
    {
        param.endpoint = resolveAutoEndpoint(r);

        if (param.endpoint == AutoEndpoint)
        {
            return result;
        }
    }

    const auto zclResult = ZCL_ReadAttributes(param, extAddr->toNumber(), nwkAddr->toNumber(), apsCtrl);

    result.isEnqueued = zclResult.isEnqueued;
    result.apsReqId = zclResult.apsReqId;
    result.sequenceNumber = zclResult.sequenceNumber;

    return result;
}

/*! A generic function to write ZCL attributes.
    The \p writeParameters is expected to contain one object (given in the device description file).

    { "fn": "zcl", "ep": endpoint, "cl": clusterId, "at": attributeId, "dt": zclDataType, "mf": manufacturerCode, "eval": expression }

    - endpoint: (optional) the destination endpoint
    - clusterId: string hex value
    - attributeId: string hex value
    - zclDataType: string hex value
    - manufacturerCode: must be set to 0x0000 for non manufacturer specific commands
    - expression: to transform the item value

    Example: "write": {"cl": "0x0000", "at": "0xff0d",  "dt": "0x20", "mf": "0x11F5", "eval": "Item.val"}
 */
bool writeZclAttribute(const Resource *r, const ResourceItem *item, deCONZ::ApsController *apsCtrl, const QVariant &writeParameters)
{
    Q_ASSERT(r);
    Q_ASSERT(item);
    Q_ASSERT(apsCtrl);

    bool result = false;
    const auto rParent = r->parentResource() ? r->parentResource() : r;
    const auto *extAddr = rParent->item(RAttrExtAddress);
    const auto *nwkAddr = rParent->item(RAttrNwkAddress);

    if (!extAddr || !nwkAddr)
    {
        return result;
    }

    const auto map = writeParameters.toMap();
    ZCL_Param param = getZclParam(map);

    if (!param.valid)
    {
        return result;
    }

    if (param.attributeCount != 1)
    {
        return result;
    }

    if (param.endpoint == AutoEndpoint)
    {
        param.endpoint = resolveAutoEndpoint(r);

        if (param.endpoint == AutoEndpoint)
        {
            return result;
        }
    }

    if (!map.contains("dt") || !map.contains("eval"))
    {
        return result;
    }

    bool ok;
    const auto dataType = variantToUint(map.value("dt"), UINT8_MAX, &ok);
    const auto expr = map.value("eval").toString();

    if (!ok || expr.isEmpty())
    {
        return result;
    }

    DBG_Printf(DBG_INFO, "writeZclAttribute, ep: 0x%02X, cl: 0x%04X, attr: 0x%04X, type: 0x%02X, mfcode: 0x%04X, expr: %s\n", param.endpoint, param.clusterId, param.attributes.front(), dataType, param.manufacturerCode, qPrintable(expr));

    deCONZ::ApsDataRequest req;
    deCONZ::ZclFrame zclFrame;

    req.setDstEndpoint(param.endpoint);
    req.setTxOptions(deCONZ::ApsTxAcknowledgedTransmission);
    req.setDstAddressMode(deCONZ::ApsNwkAddress);
    req.dstAddress().setNwk(nwkAddr->toNumber());
    req.dstAddress().setExt(extAddr->toNumber());
    req.setClusterId(param.clusterId);
    req.setProfileId(HA_PROFILE_ID);
    req.setSrcEndpoint(1); // TODO

    zclFrame.setSequenceNumber(zclNextSequenceNumber());
    zclFrame.setCommandId(deCONZ::ZclWriteAttributesId);

    if (param.manufacturerCode)
    {
        zclFrame.setFrameControl(deCONZ::ZclFCProfileCommand |
                                 deCONZ::ZclFCManufacturerSpecific |
                                 deCONZ::ZclFCDirectionClientToServer |
                                 deCONZ::ZclFCDisableDefaultResponse);
        zclFrame.setManufacturerCode(param.manufacturerCode);
    }
    else
    {
        zclFrame.setFrameControl(deCONZ::ZclFCProfileCommand |
                                 deCONZ::ZclFCDirectionClientToServer |
                                 deCONZ::ZclFCDisableDefaultResponse);
    }

    { // payload
        deCONZ::ZclAttribute attribute(param.attributes[0], dataType, QLatin1String(""), deCONZ::ZclReadWrite, true);

        if (!expr.isEmpty())
        {
            DeviceJs engine;
            engine.setResource(r);
            engine.setItem(item);

            if (engine.evaluate(expr) == JsEvalResult::Ok)
            {
                const auto res = engine.result();
                DBG_Printf(DBG_INFO, "expression: %s --> %s\n", qPrintable(expr), qPrintable(res.toString()));
                attribute.setValue(res);
            }
            else
            {
                DBG_Printf(DBG_INFO, "failed to evaluate expression for %s/%s: %s, err: %s\n", qPrintable(r->item(RAttrUniqueId)->toString()), item->descriptor().suffix, qPrintable(expr), qPrintable(engine.errorString()));
                return result;
            }
        }

        QDataStream stream(&zclFrame.payload(), QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);

        stream << attribute.id();
        stream << attribute.dataType();

        if (!attribute.writeToStream(stream))
        {
            return result;
        }
    }

    { // ZCL frame
        QDataStream stream(&req.asdu(), QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);
        zclFrame.writeToStream(stream);
    }

    result = apsCtrl->apsdeDataRequest(req) == deCONZ::Success;

    return result;
}

ParseFunction_t DA_GetParseFunction(const QVariant &params)
{
    ParseFunction_t result = nullptr;

    const std::array<ParseFunction, 5> functions =
        {
            ParseFunction("zcl", 1, parseZclAttribute),
            ParseFunction("tuya:special", 1, parseTuyaSpecial),
            ParseFunction("xiaomi:special", 1, parseXiaomiSpecial),
            ParseFunction("ias:zonestatus", 1, parseIasZoneNotificationAndStatus),
            ParseFunction("numtostr", 1, parseNumericToString)};

    QString fnName;

    if (params.type() == QVariant::Map)
    {
        const auto params1 = params.toMap();
        if (params1.isEmpty())
        {
        }
        else if (params1.contains("fn"))
        {
            fnName = params1["fn"].toString();
        }
        else
        {
            fnName = "zcl"; // default
        }
    }

    for (const auto &f : functions)
    {
        if (f.name == fnName)
        {
            result = f.fn;
            break;
        }
    }

    return result;
}

ReadFunction_t DA_GetReadFunction(const QVariant &params)
{
    ReadFunction_t result = nullptr;

    const std::array<ReadFunction, 1> functions =
        {
            ReadFunction("zcl", 1, readZclAttribute)};

    QString fnName;

    if (params.type() == QVariant::Map)
    {
        const auto params1 = params.toMap();
        if (params1.isEmpty())
        {
        }
        else if (params1.contains("fn"))
        {
            fnName = params1["fn"].toString();
        }
        else
        {
            fnName = "zcl"; // default
        }
    }

    for (const auto &f : functions)
    {
        if (f.name == fnName)
        {
            result = f.fn;
            break;
        }
    }

    return result;
}

WriteFunction_t DA_GetWriteFunction(const QVariant &params)
{
    WriteFunction_t result = nullptr;

    const std::array<WriteFunction, 1> functions =
        {
            WriteFunction("zcl", 1, writeZclAttribute)};

    QString fnName;

    if (params.type() == QVariant::Map)
    {
        const auto params1 = params.toMap();
        if (params1.isEmpty())
        {
        }
        else if (params1.contains("fn"))
        {
            fnName = params1["fn"].toString();
        }
        else
        {
            fnName = "zcl"; // default
        }
    }

    for (const auto &f : functions)
    {
        if (f.name == fnName)
        {
            result = f.fn;
            break;
        }
    }

    return result;
}

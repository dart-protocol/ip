import 'dart:typed_data';

import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:raw/raw.dart';

const Protocol tcp = Protocol(
  "TCP",
  packetFactory: _newPacket,
  ipProtocolNumber: ipProtocolTcp,
);

TcpPacket _newPacket() => TcpPacket();

class TcpPacket extends IpPayload {
  static const optionCodeEnd = 0;

  static const optionCodePadding = 1;

  static const optionCodeMaximumSegmentSize = 2;

  static const optionCodeWindowScale = 3;

  static const optionCodeSelectiveAcknowledgementPermitted = 4;

  static const optionCodeSelectiveAcknowledgement = 5;

  /// 4-byte span at index 0
  int _v0 = 0;

  /// 4-byte TCP sequence number at index 4
  int sequenceNumber = 0;

  /// 4-byte TCP acknowledgement number at index 8
  int acknowledgementNumber = 0;

  /// 4-byte span at index 12
  int _v3 = 0;

  /// 4-byte span at index 16
  int _v4 = 0;

  ByteData optionsByteData = ByteData(0);

  SelfEncoder payload = RawData.empty;

  TcpPacket();

  /// 2-byte TCP destination port.
  int get destinationPort => extractUint32Bits(_v0, 0, 0xFFFF);

  set destinationPort(int value) {
    _v0 = transformUint32Bits(_v0, 0, 0xFFFF, value);
  }

  @override
  int get hashCode => sourcePort ^ destinationPort ^ payload.hashCode;

  @override
  int get ipProtocolNumber => ipProtocolTcp;

  bool get isAck => extractUint32Bool(_v3, 20);

  set isAck(bool value) {
    _v3 = transformUint32Bool(_v3, 20, value);
  }

  bool get isFinished => extractUint32Bool(_v3, 16);

  set isFinished(bool value) {
    _v3 = transformUint32Bool(_v3, 16, value);
  }

  bool get isPush => extractUint32Bool(_v3, 19);

  set isPush(bool value) {
    _v3 = transformUint32Bool(_v3, 19, value);
  }

  bool get isReset => extractUint32Bool(_v3, 18);

  set isReset(bool value) {
    _v3 = transformUint32Bool(_v3, 18, value);
  }

  bool get isSelectiveAcknowledgementPermitted {
    return indexOfOption(optionCodeSelectiveAcknowledgementPermitted) >= 0;
  }

  set isSelectiveAcknowledgementPermitted(bool value) {
    if (value) {
      setOptionWithLength(optionCodeSelectiveAcknowledgementPermitted, 2);
    } else {
      removeOption(optionCodeSelectiveAcknowledgementPermitted);
    }
  }

  bool get isSynchronizeSequenceNumbers => extractUint32Bool(_v3, 17);

  set isSynchronizeSequenceNumbers(bool value) {
    _v3 = transformUint32Bool(_v3, 17, value);
  }

  bool get isUrgentPointer => extractUint32Bool(_v3, 21);

  set isUrgentPointer(bool value) {
    _v3 = transformUint32Bool(_v3, 21, value);
  }

  int? get maximumSegmentSize {
    final index = indexOfOption(optionCodeMaximumSegmentSize);
    if (index < 0) {
      return null;
    }
    return optionsByteData.getUint16(index + 2);
  }

  set maximumSegmentSize(int? value) {
    assert(value != null);
    final i = setOptionWithLength(optionCodeMaximumSegmentSize, 4);
    optionsByteData.setUint16(i + 2, value!);
  }

  Uint8List get optionsBytes {
    final byteData = this.optionsByteData;
    return Uint8List.view(
      byteData.buffer,
      byteData.offsetInBytes,
      byteData.lengthInBytes,
    );
  }

  set optionsBytes(Uint8List value) {
    this.optionsByteData = ByteData.view(
      value.buffer,
      value.offsetInBytes,
      value.lengthInBytes,
    );
  }

  @override
  Protocol get protocol => tcp;

  List<int>? get selectiveAcknowledgement {
    var i = indexOfOption(optionCodeSelectiveAcknowledgement);
    if (i < 0) {
      return null;
    }
    final length = (optionsByteData.getUint8(i + 1) - 2) ~/ 4;
    final result = Uint32List(length);
    i += 2;
    for (var resultIndex = 0; resultIndex < length; resultIndex++) {
      result[resultIndex] = optionsByteData.getUint32(i + 4 * resultIndex);
    }
    return result;
  }

  set selectiveAcknowledgement(List<int>? value) {
    assert(value != null);
    var i = setOptionWithLength(
        optionCodeSelectiveAcknowledgement, 2 + 4 * value!.length);
    i += 2;
    for (var item in value) {
      optionsByteData.setUint32(i, item);
      i += 4;
    }
  }

  /// 2-byte TCP source port.
  int get sourcePort => extractUint32Bits(_v0, 16, 0xFFFF);

  set sourcePort(int value) {
    _v0 = transformUint32Bits(_v0, 16, 0xFFFF, value);
  }

  int get urgentPointer => extractUint32Bits(_v4, 0, 0xFFFF);

  set urgentPointer(int value) {
    _v4 = transformUint32Bits(_v4, 0, 0xFFFF, value);
  }

  int get window => extractUint32Bits(_v3, 0, 0xFFFF);

  set window(int value) {
    _v3 = transformUint32Bits(_v3, 0, 0xFFFF, value);
  }

  int? get windowScale {
    final index = indexOfOption(optionCodeWindowScale);
    if (index < 0) {
      return null;
    }
    return optionsByteData.getUint8(index + 2);
  }

  set windowScale(int? value) {
    assert(value != null);
    final i = setOptionWithLength(optionCodeWindowScale, 3);
    optionsByteData.setUint8(i + 2, value!);
  }

  @override
  bool operator ==(other) {
    if (other is TcpPacket &&
        _v0 == other._v0 &&
        sequenceNumber == other.sequenceNumber &&
        acknowledgementNumber == other.acknowledgementNumber &&
        _v0 == other._v3 &&
        _v4 == other._v4 &&
        const ByteDataEquality()
            .equals(optionsByteData, other.optionsByteData) &&
        payload == other.payload) {
      final parent = this.parentPacket;
      final otherParent = other.parentPacket;
      if (parent == null) {
        return otherParent == null;
      }
      return parent.source == otherParent?.source &&
          parent.destination == otherParent?.destination;
    } else {
      return false;
    }
  }

  @override
  void decodeSelf(RawReader reader) {
    // 4-byte span at index 0
    _v0 = reader.readUint32();

    // 4-byte span at index 4
    sequenceNumber = reader.readUint32();

    // 4-byte span at index 8
    acknowledgementNumber = reader.readUint32();

    // 4-byte span at index 12
    _v3 = reader.readUint32();

    // 4-byte span at index 16
    _v4 = reader.readUint32();

    // Options
    // Length is determined by header length field
    final headerLength = 4 * (_v3 >> 28);
    if (headerLength < 20) {
      throw StateError("header length field has invalid value $headerLength");
    }
    final optionsLength = headerLength - 20;
    optionsByteData =
        _compressOptions(reader.readByteDataViewOrCopy(optionsLength));

    // Payload
    // Length is not determined by the header
    final payloadLength = reader.availableLengthInBytes;
    payload = RawData.decode(reader, payloadLength);
  }

  @override
  int encodeSelfCapacity() {
    var optionsLength = optionsByteData.lengthInBytes;
    while (optionsLength % 4 != 0) {
      optionsLength++;
    }
    var n = 20;
    n += optionsLength;
    n += payload.encodeSelfCapacity();
    return n;
  }

  @override
  void encodeSelf(RawWriter writer) {
    final start = writer.length;
    if (parentPacket == null) {
      throw StateError(
        "TcpPacket field 'parentPacket' is null. TCP protocol requires IP packet for calculating checksum.",
      );
    }

    // 4-byte span at index 0
    writer.writeUint32(_v0);

    // 4-byte span at index 4
    writer.writeUint32(sequenceNumber);

    // 4-byte span at index 8
    writer.writeUint32(acknowledgementNumber);

    // 4-byte span at index 12 will be set later
    writer.writeUint32(0);

    // 4-byte span at index 16
    // Checksum must have 0 during calculation.
    writer.writeUint32(0x0000FFFF & _v4);

    // Options
    final options = this.optionsByteData;
    writer.writeByteData(options);
    var headerLength = writer.length - start;

    // Adding padding
    while (headerLength % 4 != 0) {
      writer.writeUint8(0);
      headerLength++;
    }

    // We have header length
    // Set 4-byte span at index 12
    final v3 = transformUint32Bits(_v3, 28, 0xF, headerLength ~/ 4);
    writer.bufferAsByteData.setUint32(start + 12, v3);

    // Payload
    payload.encodeSelf(writer);

    // ------------
    // Set checksum
    // ------------
    int checksum = 0;
    final ipPacket = this.parentPacket;
    final ipPacketPayloadLength = writer.length - start;
    if (ipPacket is Ip4Packet) {
      checksum += ipPacket.source.asUint32;
      checksum += ipPacket.destination.asUint32;
      checksum += ipPacket.typeOfService;
      checksum += ipPacketPayloadLength;
    } else if (ipPacket is Ip6Packet) {
      checksum += _checksumIp6Address(ipPacket.source);
      checksum += _checksumIp6Address(ipPacket.destination);
      checksum += ipPacketPayloadLength;
      checksum += ipPacket.payloadProtocolNumber;
    } else {
      throw StateError("IP packet is invalid");
    }
    checksum = Ip4Packet.calculateChecksum(
      writer.bufferAsByteData,
      start,
      ipPacketPayloadLength,
      checksum: checksum,
    );
    writer.bufferAsByteData.setUint16(
        start + 16,
        Ip4Packet.calculateChecksum(
            writer.bufferAsByteData, start, writer.length - start));
  }

  int indexOfOption(int searchedCode) {
    final byteData = this.optionsByteData;
    for (var i = 0; i < byteData.lengthInBytes;) {
      final code = byteData.getUint8(i);
      if (code == searchedCode) {
        return i;
      }
      switch (code) {
        case optionCodeEnd:
          i++;
          break;
        case optionCodePadding:
          i++;
          break;
        default:
          i += byteData.getUint8(i + 1);
      }
    }
    return -1;
  }

  /// Removes all options that have the code.
  void removeOption(int code) {
    final options = this.optionsByteData;
    var newLength = options.lengthInBytes;

    while (true) {
      // Find first option of the type
      var i = this.indexOfOption(code);
      if (i < 0) {
        break;
      }
      newLength = i;

      // Skip the option
      i += options.getUint8(i + 1);

      // Move bytes of remaining options
      while (i < options.lengthInBytes) {
        options.setUint8(newLength, options.getUint8(i));
        i++;
        newLength++;
      }
    }

    // Change length
    optionsByteData =
        ByteData.view(options.buffer, options.offsetInBytes, newLength);
  }

  /// Adds the option to the TCP options.
  /// Returns index of the option.
  int setOptionWithLength(int code, int length) {
    removeOption(code);
    final oldOptions = this.optionsByteData;
    final newOptions = ByteData(oldOptions.lengthInBytes + length);
    var i = 0;
    for (; i < oldOptions.lengthInBytes; i++) {
      newOptions.setUint8(i, oldOptions.getUint8(i));
    }
    final result = i;
    newOptions.setUint8(i, code);
    if (length > 1) {
      i++;
      newOptions.setUint8(i, length);
    }
    this.optionsByteData = newOptions;
    return result;
  }

  static int _checksumIp6Address(Ip6Address address) {
    return address.v0 + address.v1 + address.v2 + address.v3;
  }

  static ByteData _compressOptions(ByteData options) {
    for (var i = 0; i < options.lengthInBytes;) {
      final code = options.getUint8(i);
      if (code == 0) {
        return ByteData.view(options.buffer, options.offsetInBytes, i);
      }
      if (code == 1) {
        continue;
      }
      i += options.getUint8(i + 1);
    }
    return options;
  }
}

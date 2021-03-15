import 'dart:typed_data';

import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:raw/raw.dart';

const Protocol ipv4 = Protocol("IPv4");

class Ip4Packet extends IpPacket<Ip4Address> {
  Ip4Packet() : super(Ip4Address.zero, Ip4Address.zero);

  /// 4-byte span at index 0
  int _v0 = 0;

  /// 4-byte span at index 4
  int _v1 = 0;

  /// 4-byte span at index 8
  int _v2 = 0;

  /// IPv4 options. Maximum length is 40 bytes.
  SelfEncoder options = RawData.empty;

  /// 3-bit flags.
  int get flags => extractUint32Bits(_v1, 13, 0x3);

  set flags(int value) {
    _v1 = transformUint32Bits(_v1, 13, 0x3, value);
  }

  /// 13-bit fragment offset.
  int get fragmentOffset => extractUint32Bits(_v1, 0, 0x1FFF);

  set fragmentOffset(int value) {
    _v1 = transformUint32Bits(_v1, 0, 0x1FFF, value);
  }

  /// 16-bit identification
  int get identification => extractUint32Bits(_v1, 16, 0xFFFF);

  set identification(int value) {
    _v1 = transformUint32Bits(_v1, 16, 0xFFFF, value);
  }

  @override
  int get ipVersion => 4;

  @override
  set payload(SelfEncoder value) {
    if (value is IpPayload) {
      payloadProtocolNumber = value.ipProtocolNumber;
    }
    super.payload = value;
  }

  @override
  int get payloadProtocolNumber => extractUint32Bits(_v2, 16, 0xFF);

  set payloadProtocolNumber(int value) {
    _v2 = transformUint32Bits(_v2, 16, 0xFF, value);
  }

  @override
  Protocol get protocol => ipv4;

  /// 8-bit time-to-live.
  int get ttl => extractUint32Bits(_v2, 24, 0xFF);

  set ttl(int value) {
    _v2 = transformUint32Bits(_v2, 0, 0xFF, value);
  }

  /// 8-bit type of service.
  int get typeOfService => extractUint32Bits(_v0, 16, 0xFF);

  set typeOfService(int value) {
    _v2 = transformUint32Bits(_v0, 16, 0xFF, value);
  }

  @override
  void decodeSelf(RawReader reader) {
    // 4-byte span at index 0
    final v0 = reader.readUint32();
    _v0 = v0;

    // Check IP version
    final version = (v0 >> 28);
    if (version != 4) {
      throw ArgumentError(
          "IPv4 packet version number should be 4, not $version");
    }

    // Get IHL
    final ihl = 0xF & (v0 >> 24);
    if (ihl < 5) {
      throw StateError("IHL has invalid value $ihl (should be between 5 and 7");
    }

    // 4-byte span at index 4
    _v1 = reader.readUint32();

    // 4-byte span at index 8
    _v2 = reader.readUint32();

    // 4-byte source address at index 12
    source = Ip4Address.decode(reader);

    // 4-byte destination address at index 16
    destination = Ip4Address.decode(reader);

    // Calculate options length
    final optionsLength = (4 * ihl) - 20;

    // Options
    options = RawData.decode(reader, optionsLength);

    // Payload
    final payloadLength = 0xFFFF & _v0;
    SelfEncoder? payload;
    final protocol = ipProtocolMap[payloadProtocolNumber];
    if (protocol != null) {
      final packetFactory = protocol.packetFactory;
      if (packetFactory != null) {
        final packet = packetFactory();
        if (packet is IpPayload) {
          packet.parentPacket = this;
        }
        packet.decodeSelf(reader.readRawReader(payloadLength));
        payload = packet;
      }
    }
    payload ??= RawData.decode(reader, payloadLength);
    super.payload = payload;
  }

  @override
  int encodeSelfCapacity() {
    var optionsLength = options.encodeSelfCapacity();
    while (optionsLength % 4 != 0) {
      optionsLength++;
    }
    return 20 + optionsLength + payload.encodeSelfCapacity();
  }

  @override
  void encodeSelf(RawWriter writer) {
    final startOfHeader = writer.length;

    // 4-byte span at index 0 will be filled in the end
    writer.writeUint32(0);

    // 4-byte span at index 4
    writer.writeUint32(_v1);

    // 4-byte span at index 8
    // checksum (2-byte span at index 10) must have 0 during calculation
    writer.writeUint32(transformUint32Bits(_v2, 0, 0xFFFF, 0));

    // 4-byte source address at index 12
    source.encodeSelf(writer);

    // 4-byte destination address at index 16
    destination.encodeSelf(writer);

    // Options
    options.encodeSelf(writer);

    // Calculate header length
    var headerLength = writer.length - startOfHeader;

    // Add padding
    while (headerLength % 4 != 0) {
      writer.writeUint8(0);
      headerLength++;
    }

    // Validate header length
    if (headerLength ~/ 4 > 15) {
      throw StateError("header length ($headerLength) exceeds maximum (60)");
    }

    // Payload
    final startOfPayload = writer.length;
    final payload = this.payload;
    if (payload is IpPayload && !identical(payload.parentPacket, this)) {
      final oldParentPacket = payload.parentPacket;
      try {
        payload.parentPacket = this;
        payload.encodeSelf(writer);
      } finally {
        payload.parentPacket = oldParentPacket;
      }
    } else {
      payload.encodeSelf(writer);
    }
    final payloadLength = writer.length - startOfPayload;
    if (payloadLength >> 16 != 0) {
      throw StateError(
          "payload length ($payloadLength) does not fit in 16-bits");
    }

    // We finally know header and payload length.
    // Set the first 4-byte span of the header.
    final v0 = (4 << 28) |
        ((headerLength ~/ 4) << 24) |
        (0x00FF0000 & _v0) |
        payloadLength;
    writer.bufferAsByteData.setUint32(startOfHeader, v0);

    // Calculate and set checksum
    final checksum =
        calculateChecksum(writer.bufferAsByteData, startOfHeader, headerLength);
    writer.bufferAsByteData.setUint16(startOfHeader + 10, checksum);
  }

  static int calculateChecksum(ByteData byteData, int index, int length,
      {int checksum = 0}) {
    while (length >= 2) {
      checksum = 0xFFFFFFFF & (checksum + byteData.getUint16(index));
      length -= 2;
      index += 2;
    }
    if (length > 0) {
      checksum += byteData.getUint8(index);
      index++;
    }
    checksum = (0xFFFF & checksum) + (checksum >> 16);
    return (0xFFFF & checksum) ^ 0xFFFF;
  }
}

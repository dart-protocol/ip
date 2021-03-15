import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:raw/raw.dart';

import 'ip6_address.dart';

const Protocol ipv6 = Protocol("IPv6");

class Ip6Packet extends IpPacket<Ip6Address> {
  Ip6Packet() : super(Ip6Address.zero, Ip6Address.zero);

  /// 32 bits at index 0
  int _v0 = 0;

  /// 32 bits at index 4
  int _v1 = 1;

  /// 20-bit flow label
  int get flowLabel => extractUint32Bits(_v0, 0, 0xFFFFF);

  set flowLabel(int value) {
    this._v0 = transformUint32Bits(_v0, 0, 0xFFFFF, value);
  }

  /// 8-bit hop limit
  int get hopLimit => extractUint32Bits(_v1, 0, 0xFF);

  set hopLimit(int value) {
    this._v1 = transformUint32Bits(_v1, 0, 0xFF, value);
  }

  @override
  int get ipVersion => 6;

  @override
  set payload(SelfEncoder value) {
    if (value is IpPayload) {
      payloadProtocolNumber = value.ipProtocolNumber;
    }
    super.payload = value;
  }

  @override
  int get payloadProtocolNumber => extractUint32Bits(_v1, 8, 0xFF);

  set payloadProtocolNumber(int value) {
    _v1 = transformUint32Bits(_v1, 8, 0xFF, value);
  }

  @override
  Protocol get protocol => ipv6;

  /// 8-bit traffic class
  int get trafficClass => extractUint32Bits(_v0, 20, 0xFF);

  set trafficClass(int value) {
    this._v0 = transformUint32Bits(_v0, 20, 0xFF, value);
  }

  @override
  void decodeSelf(RawReader reader) {
    // 4-byte span at index 0
    _v0 = reader.readUint32();

    // Check IP version
    final version = _v0 >> 28;
    if (version != 6) {
      throw ArgumentError("IP version number should be 6, not $version");
    }

    // 4-byte span at index 4
    _v1 = reader.readUint32();

    // 16-byte source IP address
    source = Ip6Address.decode(reader);

    // 16-byte destination IP address
    destination = Ip6Address.decode(reader);

    // Payload
    final payloadLength = _v1 >> 16;
    SelfEncoder? payload;
    final protocol = ipProtocolMap[payloadProtocolNumber];
    if (protocol != null) {
      final packetFactory = protocol.packetFactory;
      if (packetFactory != null) {
        final packet = packetFactory();
        if (packet is IpPayload) {
          packet.parentPacket = this;
        }
        packet.decodeSelf(reader);
        payload = packet;
      }
    }
    payload ??= RawData.decode(reader, payloadLength);
    super.payload = payload;
  }

  @override
  int encodeSelfCapacity() => 40 + payload.encodeSelfCapacity();

  @override
  void encodeSelf(RawWriter writer) {
    final start = writer.length;

    // 4-byte span at index 0
    // We add IP version number (6)
    writer.writeUint32(transformUint32Bits(_v0, 28, 0xF, 6));

    // 4-byte span at index 4
    // We will set payload length later
    writer.writeUint32(_v1);

    // 16-byte source IP address
    source.encodeSelf(writer);

    // 16-byte destination IP address
    destination.encodeSelf(writer);

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
      throw StateError("payload length does not fit in 16 bits");
    }

    // Set payload length
    writer.bufferAsByteData.setUint16(start + 4, payloadLength);
  }
}

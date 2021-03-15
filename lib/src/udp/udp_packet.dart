import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:raw/raw.dart';

const Protocol udp = Protocol(
  "UDP",
  packetFactory: _newPacket,
  ipProtocolNumber: ipProtocolUdp,
);

UdpPacket _newPacket() => UdpPacket();

class UdpPacket extends IpPayload {
  /// UDP packet destination port.
  int destinationPort = 0;

  /// UDP packet source port.
  int sourcePort = 0;

  /// UDP packet payload.
  SelfEncoder payload = RawData.empty;

  UdpPacket();

  @override
  int get hashCode {
    return sourcePort ^ destinationPort ^ payload.hashCode;
  }

  @override
  int get ipProtocolNumber => ipProtocolUdp;

  @override
  Protocol get protocol => udp;

  @override
  operator ==(other) {
    if (other is UdpPacket &&
        sourcePort == other.sourcePort &&
        destinationPort == other.destinationPort &&
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
    // 16-bit source port
    sourcePort = reader.readUint16();

    // 16-bit destination port
    destinationPort = reader.readUint16();

    // 16-bit payload length
    final payloadLength = reader.readUint16();

    // 16-bit checksum (ignored)
    reader.readUint16();

    // Payload
    payload = RawData.decode(reader, payloadLength);
  }

  @override
  int encodeSelfCapacity() => 8 + payload.encodeSelfCapacity();

  @override
  void encodeSelf(RawWriter writer) {
    // ----------------------------
    // Check that we have IP packet
    // ----------------------------
    if (parentPacket == null) {
      throw StateError(
        "UdpPacket field 'parentPacket' is null. UDP protocol requires IP packet for calculating checksum.",
      );
    }

    // ------
    // Fields
    // ------
    final start = writer.length;

    // 16-bit source port
    writer.writeUint16(sourcePort);

    // 16-bit destination port
    writer.writeUint16(destinationPort);

    // 16-bit payload length will be filled later
    writer.writeUint16(0);

    // 16-bit checksum
    // Must have 0 during calculation
    writer.writeUint16(0);

    // -------
    // Payload
    // -------
    final payloadStart = writer.length;
    payload.encodeSelf(writer);
    final payloadLength = writer.length - payloadStart;

    // Set payload length
    writer.bufferAsByteData.setUint16(start + 4, payloadLength);

    // ------------------
    // Calculate checksum
    // ------------------
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

    // Set checksum
    writer.bufferAsByteData.setUint16(start + 6, checksum);
  }

  static int _checksumIp6Address(Ip6Address address) {
    return address.v0 + address.v1 + address.v2 + address.v3;
  }
}

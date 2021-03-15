import 'dart:typed_data';

import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';

import 'ip6_packet.dart';

class Ip6Address extends IpAddress {
  static final Ip6Address any = zero;
  static final Ip6Address zero = Ip6Address.parse("::");
  static final Ip6Address broadcast = Ip6Address.parse("1::");
  static final Ip6Address loopback = Ip6Address.parse("::1");

  final int v0;
  final int v1;
  final int v2;
  final int v3;

  Ip6Address._(this.v0, this.v1, this.v2, this.v3);

  factory Ip6Address.decode(RawReader reader) {
    return Ip6Address._(
      reader.readUint32(),
      reader.readUint32(),
      reader.readUint32(),
      reader.readUint32(),
    );
  }

  factory Ip6Address.fromBytes(List<int> bytes, int index) {
    return Ip6Address.decode(RawReader.withBytes(bytes));
  }

  @override
  int encodeSelfCapacity() => 16;

  @override
  void encodeSelf(RawWriter writer) {
    // 4-byte span at index 0
    writer.writeUint32(v0);

    // 4-byte span at index 4
    writer.writeUint32(v1);

    // 4-byte span at index 8
    writer.writeUint32(v2);

    // 4-byte span at index 12
    writer.writeUint32(v3);
  }

  @override
  bool get isIpv4 {
    return v0 == 0 && v1 == 0 && v2 == 0xFF;
  }

  @override
  bool get isLocalNetwork {
    if (isIpv4) {
      return Ip4Address.fromUint32(v3).isLocalNetwork;
    }
    return false;
  }

  @override
  bool get isLoopback => this == loopback;

  @override
  Protocol get protocol => ipv6;

  @override
  String toString() {
    // ---------------------------
    // Find longest span of zeroes
    // ---------------------------
    final bytes = this.toImmutableBytes();

    // Longest seen span
    int? longestStart;
    var longestLength = 0;

    // Current span
    int? start;
    var length = 0;

    // Iterate
    for (var i = 0; i < 16; i++) {
      if (bytes[i] == 0) {
        // Zero byte
        if (start == null) {
          if (i % 2 == 0) {
            // First byte of a span
            start = i;
            length = 1;
          }
        } else {
          length++;
        }
      } else if (start != null) {
        // End of a span
        if (length > longestLength) {
          // Longest so far
          longestStart = start;
          longestLength = length;
        }
        start = null;
      }
    }
    if (start != null && length > longestLength) {
      // End of the longest span
      longestStart = start;
      longestLength = length;
    }

    // Longest length must be a whole group
    longestLength -= longestLength % 2;

    // Ignore longest zero span if it's less than 4 bytes.
    if (longestLength < 4) {
      longestStart = null;
    }

    // ----
    // Print
    // -----
    final sb = StringBuffer();
    var colon = false;
    for (var i = 0; i < 16; i++) {
      if (i == longestStart) {
        sb.write("::");
        i += longestLength - 1;
        colon = false;
        continue;
      }
      final byte = bytes[i];
      if (i % 2 == 0) {
        //
        // First byte of a group
        //
        if (colon) {
          sb.write(":");
        } else {
          colon = true;
        }
        if (byte != 0) {
          sb.write(byte.toRadixString(16));
        }
      } else {
        //
        // Second byte of a group
        //
        // If this is a single-digit number and the previous byte was non-zero,
        // we must add zero
        if (byte < 16 && bytes[i - 1] != 0) {
          sb.write("0");
        }
        sb.write(byte.toRadixString(16));
      }
    }
    return sb.toString();
  }

  static Ip6Address parse(String source) {
    final result = ByteData(16);
    final middle = source.indexOf("::");
    List<String> prefixParts = const <String>[];
    List<String> suffixParts = const <String>[];
    if (middle < 0) {
      prefixParts = source.split(":");
    } else {
      if (middle != 0) {
        prefixParts = source.substring(0, middle).split(":");
      }
      if (middle + 2 != source.length) {
        suffixParts = source.substring(middle + 2).split(":");
      }
    }
    if (prefixParts.length + suffixParts.length > 8) {
      throw ArgumentError.value(source, "source", "too many numbers");
    }
    var i = 0;
    for (var item in prefixParts) {
      try {
        result.setUint16(i, int.parse(item, radix: 16));
      } catch (e) {
        throw ArgumentError.value(source, "source", "problem with '$item'");
      }
      i += 2;
    }
    i = 16 - suffixParts.length * 2;
    for (var item in suffixParts) {
      try {
        result.setUint16(i, int.parse(item, radix: 16));
      } catch (e) {
        throw ArgumentError.value(source, "source", "problem with '$item'");
      }
      i += 2;
    }
    return Ip6Address.decode(RawReader.withByteData(result));
  }
}

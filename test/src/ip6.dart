import 'dart:typed_data';

import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:ip/udp.dart';
import 'package:raw/raw.dart';
import 'package:raw/test_helpers.dart';
import 'package:test/test.dart';

void main() {
  group("Ipv6Address:", () {
    group("parse:", () {
      test("'0123:4567:89ab:cdef:0123:4567:89ab:cdef'", () {
        final actual =
            Ip6Address.parse("0123:4567:89ab:cdef:0123:4567:89ab:cdef")
                .toImmutableBytes();
        final expected = Uint8List(16);
        expected[0] = 0x01;
        expected[1] = 0x23;
        expected[2] = 0x45;
        expected[3] = 0x67;
        expected[4] = 0x89;
        expected[5] = 0xAB;
        expected[6] = 0xCD;
        expected[7] = 0xEF;
        expected[8] = 0x01;
        expected[9] = 0x23;
        expected[10] = 0x45;
        expected[11] = 0x67;
        expected[12] = 0x89;
        expected[13] = 0xAB;
        expected[14] = 0xCD;
        expected[15] = 0xEF;
        expect(actual, orderedEquals(expected));
      });

      test("'::'", () {
        final actual = Ip6Address.parse("::").toImmutableBytes();
        final expected = Uint8List(16);
        expect(actual, orderedEquals(expected));
      });

      test("'1::'", () {
        final actual = Ip6Address.parse("1::").toImmutableBytes();
        final expected = Uint8List(16);
        expected[1] = 1;
        expect(actual, orderedEquals(expected));
      });

      test("'::1'", () {
        final actual = Ip6Address.parse("::1").toImmutableBytes();
        final expected = Uint8List(16);
        expected[15] = 1;
        expect(actual, orderedEquals(expected));
      });

      test("'abcd:ef01::'", () {
        final actual = Ip6Address.parse("abcd:ef01::").toImmutableBytes();
        final expected = Uint8List(16);
        expected[0] = 0xAB;
        expected[1] = 0xCD;
        expected[2] = 0xEF;
        expected[3] = 0x01;
        expect(actual, orderedEquals(expected));
      });

      test("'::abcd:ef01'", () {
        final actual = Ip6Address.parse("::abcd:ef01").toImmutableBytes();
        final expected = Uint8List(16);
        expected[12] = 0xAB;
        expected[13] = 0xCD;
        expected[14] = 0xEF;
        expected[15] = 0x01;
        expect(actual, orderedEquals(expected));
      });
    });

    test("toString: '0123:4567:89ab:cdef:0123:4567:89ab:cdef'", () {
      var address = Ip6Address.parse("123:4567:89ab:cdef:0123:4567:89ab:cdef");
      expect(
          address.toString(), equals("123:4567:89ab:cdef:123:4567:89ab:cdef"));
    });

    test("toString: '::'", () {
      var address = Ip6Address.parse("::");
      expect(address.toString(), equals("::"));
    });

    test("toString: '1::'", () {
      var address = Ip6Address.parse("1::");
      expect(address.toString(), equals("1::"));
    });

    test("toString: '::1'", () {
      var address = Ip6Address.parse("::1");
      expect(address.toString(), equals("::1"));
    });

    test("toString: '1::1'", () {
      var address = Ip6Address.parse("1::1");
      expect(address.toString(), equals("1::1"));
    });

    test("toString: '1:0:0:2::3:0:0:4'", () {
      var address = Ip6Address.parse("1:0:2::3:0:4");
      expect(address.toString(), equals("1:0:2::3:0:4"));
    });

    test("toString: '1:2:3:4:5:6:ff00:0'", () {
      var address = Ip6Address.parse("1:2:3:4:5:6:ff00:0");
      expect(address.toString(), equals("1:2:3:4:5:6:ff00:0"));
    });

    test("toString: '1:2:3:4:5:ff00:0:0'", () {
      var address = Ip6Address.parse("1:2:3:4:5:ff00:0:0");
      expect(address.toString(), equals("1:2:3:4:5:ff00::"));
    });
  });

  group("Ipv6Packet:", () {
    group("default", () {
      final example = Ip6Packet();
      test("encode, decode", () {
        // Test that this doesn't throw
        final bytes = example.toImmutableBytes();

        // Test reading written default bytes
        final decoded = Ip6Packet();
        decoded.decodeSelf(RawReader.withBytes(bytes));

        // Test equality
        expect(decoded.toImmutableBytes(),
            orderedEquals(example.toImmutableBytes()));
        expect(decoded, equals(example));
      });
    });

    test("payload auto-decoding", () {
      final example = Ip6Packet();
      expect(example.payloadProtocolNumber, 0);

      // Set UDP payload
      example.payload = UdpPacket();
      expect(example.payloadProtocolNumber, ipProtocolUdp);

      // Test that this doesn't throw
      final encoded = example.toImmutableBytes();

      // Test reading written default bytes
      final decoded = Ip6Packet();
      decoded.decodeSelf(RawReader.withBytes(encoded));

      // Test equality
      expect(decoded, selfEncoderEquals(example));

      // Test that the payload is UDP
      expect(decoded.payload, const TypeMatcher<UdpPacket>());
    });

    group("example #1", () {
      late List<int> exampleBytes;
      late Ip6Packet example;

      setUp(() {
        exampleBytes = const [
          // 4-bit version, 8-bit traffic class, 20-bit flow label
          0x6F,
          0xE1,
          2,
          3,

          // Payload length
          0,
          3,
          // Next header
          0x04,
          // Hop limit
          0x05,

          // Source
          0,
          1,
          2,
          3,

          4,
          5,
          6,
          7,

          8,
          9,
          10,
          11,

          12,
          13,
          14,
          15,

          // Destination
          0x00,
          0x10,
          0x20,
          0x30,

          0x40,
          0x50,
          0x60,
          0x70,

          0x80,
          0x90,
          0xA0,
          0xB0,

          0xC0,
          0xD0,
          0xE0,
          0xF0,

          // Payload
          1,
          2,
          3,
        ];
        example = Ip6Packet();
        example.trafficClass = 0xFE;
        example.flowLabel = 0x010203;
        example.payloadProtocolNumber = 0x04;
        example.hopLimit = 0x05;
        example.source =
            Ip6Address.parse("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f");
        example.destination =
            Ip6Address.parse("0010:2030:4050:6070:8090:a0b0:c0d0:e0f0");
        example.payload = RawData([1, 2, 3]);
      });

      test("encode, decode, encode", () {
        // encode
        final writer = RawWriter.withCapacity(500);
        example.encodeSelf(writer);
        final encoded = writer.toUint8ListView();
        expect(encoded, byteListEquals(exampleBytes));
        final encodedReader = RawReader.withBytes(encoded);

        // encode -> decode
        final decoded = Ip6Packet();
        decoded.decodeSelf(encodedReader);

        // encode -> decode -> encode
        // (the next two lines should both encode)
        expect(decoded.toImmutableBytes(), byteListEquals(exampleBytes));
        expect(decoded, selfEncoderEquals(example));
        expect(encodedReader.availableLengthInBytes, 0);
      });

      test("decode", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = Ip6Packet();
        decoded.decodeSelf(reader);
        expect(decoded, selfEncoderEquals(example));
        expect(reader.availableLengthInBytes, 0);
      });

      test("decoded properties", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = Ip6Packet();
        decoded.decodeSelf(reader);
        expect(decoded.ipVersion, equals(6));
        expect(decoded.trafficClass, equals(0xFE));
        expect(decoded.flowLabel, equals(0x10203));
        expect(decoded.payloadProtocolNumber, equals(0x04));
        expect(decoded.hopLimit, equals(0x05));
        expect(
          decoded.source,
          equals(Ip6Address.parse("0001:0203:0405:0607:0809:0a0b:0c0d:0e0f")),
        );
        expect(
          decoded.destination,
          equals(Ip6Address.parse("0010:2030:4050:6070:8090:a0b0:c0d0:e0f0")),
        );
        expect(decoded.payload, equals(RawData([1, 2, 3])));
      });
    });
  });
}

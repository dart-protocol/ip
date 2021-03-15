import 'dart:typed_data';

import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:ip/udp.dart';
import 'package:raw/raw.dart';
import 'package:raw/test_helpers.dart';
import 'package:test/test.dart';

void main() {
  group("Ipv4Address", () {
    test("parse", () {
      final address = Ip4Address.parse("255.254.253.252");
      expect(
        address.toImmutableBytes(),
        orderedEquals([255, 254, 253, 252]),
      );
    });

    test("asUint32", () {
      final address = Ip4Address.parse("255.254.253.252");
      expect(address.asUint32, equals(0xFFFEFDFC));
    });

    test("toString", () {
      var address = Ip4Address.parse("255.254.253.252");
      expect(address.toString(), equals("255.254.253.252"));
    });
  });

  group("Ipv4Packet", () {
    test("checksum calculation", () {
      final bytes = Uint8List.fromList(const DebugHexDecoder().convert(
        "4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7",
      ));
      final byteData = ByteData.view(bytes.buffer);
      final checksum =
          Ip4Packet.calculateChecksum(byteData, 0, byteData.lengthInBytes);
      expect(checksum, 0xB861);
    });

    group("default", () {
      final example = Ip4Packet();
      test("encode, decode", () {
        // Test that this doesn't throw
        final bytes = example.toImmutableBytes();

        // Test reading written default bytes
        final decoded = Ip4Packet();
        decoded.decodeSelf(RawReader.withBytes(bytes));

        // Test equality
        expect(decoded, selfEncoderEquals(example));
      });
    });

    test("payload auto-decoding", () {
      final example = Ip4Packet();
      expect(example.payloadProtocolNumber, 0);

      // Set UDP payload
      example.payload = UdpPacket();
      expect(example.payloadProtocolNumber, ipProtocolUdp);

      // Test that this doesn't throw
      final encoded = example.toImmutableBytes();

      // Test reading written default bytes
      final decoded = Ip4Packet();
      decoded.decodeSelf(RawReader.withBytes(encoded));

      // Test equality
      expect(decoded, selfEncoderEquals(example));

      // Test that the payload is UDP
      expect(decoded.payload, const TypeMatcher<UdpPacket>());
    });

    group("example #1", () {
      late List<int> exampleBytes;
      late Ip4Packet example;

      setUp(() {
        exampleBytes = const [
          0x46, // 4-bit version, 4-bit IHL
          0x00, // Type of service
          0, // Total length
          3,

          0, // Identification
          0,
          0, // 3-bit flags, Fragment offset
          0,

          0, // TTL
          0, // Protocol
          0x91, // Checksum
          0xEC,

          0x0A, // Source
          0x01,
          0x02,
          0x03,

          0x0A, // Destination
          0x03,
          0x02,
          0x01,

          // Options
          7,
          8,
          9,
          0,

          // Payload
          1,
          2,
          3,
        ];
        example = Ip4Packet();
        example.ttl = 0;
        example.source = Ip4Address.parse("10.1.2.3");
        example.destination = Ip4Address.parse("10.3.2.1");
        example.options = RawData([7, 8, 9, 0]);
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
        final decoded = Ip4Packet();
        decoded.decodeSelf(encodedReader);

        // encode -> decode -> encode
        // (the next two lines should both encode)
        expect(decoded.toImmutableBytes(), byteListEquals(exampleBytes));
        expect(decoded, selfEncoderEquals(example));
        expect(encodedReader.availableLengthInBytes, 0);
      });

      test("decode", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = Ip4Packet();
        decoded.decodeSelf(reader);
        expect(decoded, selfEncoderEquals(example));
        expect(reader.availableLengthInBytes, 0);
      });

      test("decoded properties", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = Ip4Packet();
        decoded.decodeSelf(reader);
        expect(decoded.ipVersion, equals(4));
        expect(decoded.typeOfService, equals(0));
        expect(decoded.identification, equals(0));
        expect(decoded.source, equals(Ip4Address.parse("10.1.2.3")));
        expect(decoded.destination, equals(Ip4Address.parse("10.3.2.1")));
        expect(decoded.options, selfEncoderEqualsBytes([7, 8, 9, 0]));
        expect(decoded.payload, selfEncoderEqualsBytes([1, 2, 3]));
      });
    });
  });
}

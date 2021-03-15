import 'package:ip/foundation.dart';
import 'package:ip/ip.dart';
import 'package:ip/tcp.dart';
import 'package:raw/raw.dart';
import 'package:raw/test_helpers.dart';
import 'package:test/test.dart';

void main() {
  group("TcpPacket", () {
    test("comparison doesn't need parent packet", () {
      final a = TcpPacket();
      final b = TcpPacket();
      expect(a, b);
      b.windowScale = 1;
      expect(a, isNot(b));
    });

    group("default", () {
      final example = TcpPacket();
      example.parentPacket = Ip4Packet();

      test("encode, decode", () {
        final reader = RawReader.withBytes(example.toImmutableBytes());
        final decoded = TcpPacket();
        decoded.parentPacket = example.parentPacket;
        decoded.decodeSelf(reader);
        expect(decoded, selfEncoderEquals(example));
        expect(reader.availableLengthInBytes, 0);
      });
    });

    group("example #1", () {
      late List<int> exampleBytes;
      late TcpPacket example;

      setUp(() {
        exampleBytes = <int>[
          0xFE, // source port
          0xDC,
          0xBA, // destination port
          0x98,

          0x76, // sequence number
          0x54,
          0x32,
          0x10,

          0xAB, // acknowledgement number
          0xBA,
          0xAC,
          0xCA,

          0x70, // 4-bit header length, reserved bits, flags
          0x00,
          0x12, // window
          0x34,

          0xB2, // checksum
          0x61,
          0x00, // urgent pointer
          0x00,

          // Options
          // window scale
          TcpPacket.optionCodeWindowScale,
          3,
          4,
          // maximum segment size
          TcpPacket.optionCodeMaximumSegmentSize,

          4,
          0,
          5,
          0,

          // Payload
          1,
          2,
          3,
        ];

        final exampleIpPacket = Ip4Packet();
        exampleIpPacket.source = Ip4Address.loopback;
        exampleIpPacket.destination = Ip4Address.loopback;

        example = TcpPacket();
        example.parentPacket = exampleIpPacket;
        example.sourcePort = 0xFEDC;
        example.destinationPort = 0xBA98;
        example.sequenceNumber = 0x76543210;
        example.acknowledgementNumber = 0xABBAACCA;
        example.window = 0x1234;
        example.urgentPointer = 0;
        example.windowScale = 4;
        example.maximumSegmentSize = 5;
        example.payload = RawData([1, 2, 3]);
      });

      test("encode, decode, encode", () {
        // encode
        // (to middle of the buffer)
        final writer = RawWriter.withCapacity(500);
        example.encodeSelf(writer);
        final encoded = writer.toUint8ListView();
        expect(encoded, byteListEquals(exampleBytes));
        final encodedReader = RawReader.withBytes(encoded);

        // encode -> decode
        final decoded = TcpPacket();
        decoded.parentPacket = example.parentPacket;
        decoded.decodeSelf(encodedReader);

        // encode -> decode -> encode
        // (the next two lines should both encode)
        expect(decoded.toImmutableBytes(), byteListEquals(exampleBytes));
        expect(decoded, selfEncoderEquals(example));
        expect(encodedReader.availableLengthInBytes, 0);
      });

      test("decode", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = TcpPacket();
        decoded.parentPacket = example.parentPacket;
        decoded.decodeSelf(reader);
        expect(decoded, selfEncoderEquals(example));
        expect(reader.availableLengthInBytes, 0);
      });

      test("decoded properties", () {
        final reader = RawReader.withBytes(exampleBytes);
        final decoded = TcpPacket();
        decoded.decodeSelf(reader);
        expect(decoded.sourcePort, equals(0xFEDC));
        expect(decoded.destinationPort, equals(0xBA98));
        expect(decoded.sequenceNumber, equals(0x76543210));
        expect(decoded.acknowledgementNumber, equals(0xABBAACCA));
        expect(decoded.window, equals(0x1234));
        expect(
            decoded.optionsBytes,
            byteListEquals([
              TcpPacket.optionCodeWindowScale,
              3,
              4,
              // maximum segment size
              TcpPacket.optionCodeMaximumSegmentSize,

              4,
              0,
              5,
            ]));
        expect(decoded.payload, equals(RawData([1, 2, 3])));
      });
    });
  });
}

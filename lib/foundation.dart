library ip.foundation;

import 'package:raw/raw.dart';

export 'package:raw/raw.dart'
    show SelfEncoder, SelfDecoder, RawWriter, RawReader;

abstract class Packet extends SelfCodec {
  Protocol get protocol;
}

class Protocol {
  final String name;
  final PacketFactory? packetFactory;
  final int? ipProtocolNumber;

  const Protocol(this.name, {this.packetFactory, this.ipProtocolNumber});
}

typedef PacketFactory = Packet Function();

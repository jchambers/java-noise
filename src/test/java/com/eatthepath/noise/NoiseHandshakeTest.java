package com.eatthepath.noise;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  @Test
  void getOutboundMessageLength() throws NoSuchPatternException {
    final HandshakePattern handshakePattern = HandshakePattern.getInstance("XX");

    final int publicKeyLength = 56;

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(56, NoiseHandshake.getOutboundMessageLength(handshakePattern, 0, publicKeyLength, 0));
    assertEquals(144, NoiseHandshake.getOutboundMessageLength(handshakePattern, 1, publicKeyLength, 0));
    assertEquals(88, NoiseHandshake.getOutboundMessageLength(handshakePattern, 2, publicKeyLength, 0));

    assertEquals(59, NoiseHandshake.getOutboundMessageLength(handshakePattern, 0, publicKeyLength, 3));
    assertEquals(149, NoiseHandshake.getOutboundMessageLength(handshakePattern, 1, publicKeyLength, 5));
    assertEquals(95, NoiseHandshake.getOutboundMessageLength(handshakePattern, 2, publicKeyLength, 7));
  }

  @Test
  void getPayloadLength() throws NoSuchPatternException {
    final HandshakePattern handshakePattern = HandshakePattern.getInstance("XX");

    final int publicKeyLength = 56;

    // Expected lengths via https://noiseprotocol.org/noise.html#message-format
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 56));
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 1, publicKeyLength, 144));
    assertEquals(0, NoiseHandshake.getPayloadLength(handshakePattern, 2, publicKeyLength, 88));

    assertEquals(3, NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 59));
    assertEquals(5, NoiseHandshake.getPayloadLength(handshakePattern, 1, publicKeyLength, 149));
    assertEquals(7, NoiseHandshake.getPayloadLength(handshakePattern, 2, publicKeyLength, 95));

    assertThrows(IllegalArgumentException.class,
        () -> NoiseHandshake.getPayloadLength(handshakePattern, 0, publicKeyLength, 55));
  }
}
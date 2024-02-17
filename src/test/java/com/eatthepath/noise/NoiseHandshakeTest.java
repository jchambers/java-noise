package com.eatthepath.noise;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class NoiseHandshakeTest {

  @Test
  void getOutboundMessageLength() {
    final HandshakePattern handshakePattern = handshakePatternFromString("""
        -> e
        <- e, ee, s, es
        -> s, se
        """);

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
  void getPayloadLength() {
    final HandshakePattern handshakePattern = handshakePatternFromString("""
        -> e
        <- e, ee, s, es
        -> s, se
        """);

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

  private HandshakePattern handshakePatternFromString(final String patternString) {
    final HandshakePattern.MessagePattern[] messagePatterns = patternString.lines()
        .map(String::trim)
        .map(line -> {
          final NoiseHandshake.Role sender;

          if (line.startsWith("-> ")) {
            sender = NoiseHandshake.Role.INITIATOR;
          } else if (line.startsWith("<- ")) {
            sender = NoiseHandshake.Role.RESPONDER;
          } else {
            throw new IllegalArgumentException("Could not identify sender");
          }

          final HandshakePattern.Token[] tokens = Arrays.stream(line.substring(3).split(","))
              .map(String::trim)
              .map(HandshakePattern.Token::fromString)
              .toList()
              .toArray(new HandshakePattern.Token[0]);

          return new HandshakePattern.MessagePattern(sender, tokens);
        })
        .toList()
        .toArray(new HandshakePattern.MessagePattern[0]);

    return new HandshakePattern(new HandshakePattern.MessagePattern[0], messagePatterns);
  }
}
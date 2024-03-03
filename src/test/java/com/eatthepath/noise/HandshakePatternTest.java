package com.eatthepath.noise;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Collections;
import java.util.List;

import static com.eatthepath.noise.HandshakePattern.MessagePattern;
import static com.eatthepath.noise.HandshakePattern.Token;
import static com.eatthepath.noise.NoiseHandshake.Role;

import static org.junit.jupiter.api.Assertions.*;

class HandshakePatternTest {

  @Test
  void getInstance() throws NoSuchPatternException {
    {
      final HandshakePattern expectedXXPattern = HandshakePattern.fromString("""
          XX:
            -> e
            <- e, ee, s, es
            -> s, se
          """);

      assertEquals(expectedXXPattern, HandshakePattern.getInstance("XX"));
    }


    {
      final HandshakePattern expectedXXFallbackPsk0Pattern =HandshakePattern.fromString("""
          XXfallback+psk0:
            -> e
            ...
            <- psk, e, ee, s, es
            -> s, se
          """);

      assertEquals(expectedXXFallbackPsk0Pattern, HandshakePattern.getInstance("XXfallback+psk0"));
    }

    assertThrows(NoSuchPatternException.class,
        () -> HandshakePattern.getInstance("This is not a legitimate Noise handshake pattern"));
  }

  @Test
  void fromString() {
    {
      final HandshakePattern expectedXXPattern = new HandshakePattern("XX",
          new MessagePattern[0],
          new MessagePattern[]{
              new MessagePattern(Role.INITIATOR, new Token[]{Token.E}),
              new MessagePattern(Role.RESPONDER, new Token[]{Token.E, Token.EE, Token.S, Token.ES}),
              new MessagePattern(Role.INITIATOR, new Token[]{Token.S, Token.SE}),
          });

      assertEquals(expectedXXPattern, HandshakePattern.fromString("""
          XX:
            -> e
            <- e, ee, s, es
            -> s, se
          """));
    }

    {
      final HandshakePattern expectedKKPattern = new HandshakePattern("KK",
          new MessagePattern[] {
              new MessagePattern(Role.INITIATOR, new Token[]{Token.S}),
              new MessagePattern(Role.RESPONDER, new Token[]{Token.S}),
          },
          new MessagePattern[] {
              new MessagePattern(Role.INITIATOR, new Token[]{Token.E, Token.ES, Token.SS}),
              new MessagePattern(Role.RESPONDER, new Token[]{Token.E, Token.EE, Token.SE})
          });

      assertEquals(expectedKKPattern, HandshakePattern.fromString("""
          KK:
            -> s
            <- s
            ...
            -> e, es, ss
            <- e, ee, se
          """));
    }
  }

  @ParameterizedTest
  @CsvSource({
      "XX,XX",
      "I1K,I1K",
      "XXfallback+psk0,XX",
      "Npsk0,N"
  })
  void getFundamentalPatternName(final String fullPatternName, final String expectedfundamentalPatternName) {
    assertEquals(expectedfundamentalPatternName, HandshakePattern.getFundamentalPatternName(fullPatternName));
  }

  @ParameterizedTest
  @MethodSource
  void getModifiers(final String fullPatternName, final List<String> expectedModifiers) {
    assertEquals(expectedModifiers, HandshakePattern.getModifiers(fullPatternName));
  }

  private static List<Arguments> getModifiers() {
    return List.of(
        Arguments.of("XX", Collections.emptyList()),
        Arguments.of("XXfallback+psk0", List.of("fallback", "psk0")),
        Arguments.of("Npsk0", List.of("psk0"))
    );
  }

  @Test
  void withFallbackModifier() throws NoSuchPatternException {
    final HandshakePattern expectedXXFallbackPattern = HandshakePattern.fromString("""
        XXfallback:
          -> e
          ...
          <- e, ee, s, es
          -> s, se
        """);

    assertEquals(expectedXXFallbackPattern,  HandshakePattern.getInstance("XX").withModifier("fallback"));
  }

  @Test
  void withPskModifier() throws NoSuchPatternException {
    {
      final HandshakePattern expectedNKPsk0Pattern = HandshakePattern.fromString("""
          NKpsk0:
            <- s
            ...
            -> psk, e, es
            <- e, ee
          """);

      assertEquals(expectedNKPsk0Pattern, HandshakePattern.getInstance("NK").withModifier("psk0"));
    }

    {
      final HandshakePattern expectedXXPsk3Pattern = HandshakePattern.fromString("""
          XXpsk3:
            -> e
            <- e, ee, s, es
            -> s, se, psk
          """);

      assertEquals(expectedXXPsk3Pattern, HandshakePattern.getInstance("XX").withModifier("psk3"));
    }
  }

  @Test
  void withModifierUnrecognized() {
    assertThrows(IllegalArgumentException.class, () -> HandshakePattern.getInstance("XX").withModifier("fancy"));
  }

  @ParameterizedTest
  @MethodSource
  void isValidFallbackMessagePattern(final MessagePattern messagePattern, final boolean expectValidFallbackMessagePattern) {
    assertEquals(expectValidFallbackMessagePattern, HandshakePattern.isValidFallbackMessagePattern(messagePattern));
  }

  private static List<Arguments> isValidFallbackMessagePattern() {
    return List.of(
        Arguments.of(new MessagePattern(Role.INITIATOR, new Token[] { Token.E }), true),
        Arguments.of(new MessagePattern(Role.INITIATOR, new Token[] { Token.S }), true),
        Arguments.of(new MessagePattern(Role.INITIATOR, new Token[] { Token.E, Token.S }), true),
        Arguments.of(new MessagePattern(Role.RESPONDER, new Token[] { Token.E }), false),
        Arguments.of(new MessagePattern(Role.RESPONDER, new Token[] { Token.S }), false),
        Arguments.of(new MessagePattern(Role.RESPONDER, new Token[] { Token.E, Token.S }), false),
        Arguments.of(new MessagePattern(Role.INITIATOR, new Token[] { Token.EE }), false),
        Arguments.of(new MessagePattern(Role.INITIATOR, new Token[] { Token.E, Token.S, Token.EE }), false)
    );
  }

  @Test
  void isOneWayPattern() throws NoSuchPatternException {
    assertTrue(HandshakePattern.getInstance("N").isOneWayPattern());
    assertFalse(HandshakePattern.getInstance("NK").isOneWayPattern());
  }

  @Test
  void isFallbackPattern() throws NoSuchPatternException {
    assertTrue(HandshakePattern.getInstance("XXfallback").isFallbackPattern());
    assertFalse(HandshakePattern.getInstance("XX").isFallbackPattern());
  }

  @Test
  void isPreSharedKeyHandshake() throws NoSuchPatternException {
    assertFalse(HandshakePattern.getInstance("N").isPreSharedKeyHandshake());
    assertTrue(HandshakePattern.getInstance("Npsk0").isPreSharedKeyHandshake());

    assertFalse(HandshakePattern.getInstance("NN").isPreSharedKeyHandshake());
    assertTrue(HandshakePattern.getInstance("NNpsk2").isPreSharedKeyHandshake());
  }

  @ParameterizedTest
  @CsvSource({
      "N, 0",
      "NN, 0",
      "Npsk0, 1",
      "NNpsk2, 1",
      "NNpsk0+psk2, 2"
  })
  void getRequiredPreSharedKeyCount(final String handshakePatternName, final int expectedRequiredPreSharedKeyCount) throws NoSuchPatternException {
    assertEquals(expectedRequiredPreSharedKeyCount,
        HandshakePattern.getInstance(handshakePatternName).getRequiredPreSharedKeyCount());
  }

  @Test
  void requiresLocalStaticKeyPair() throws NoSuchPatternException {
    assertTrue(HandshakePattern.getInstance("XN").requiresLocalStaticKeyPair(Role.INITIATOR));
    assertFalse(HandshakePattern.getInstance("XN").requiresLocalStaticKeyPair(Role.RESPONDER));

    assertTrue(HandshakePattern.getInstance("NX").requiresLocalStaticKeyPair(Role.RESPONDER));
    assertFalse(HandshakePattern.getInstance("NX").requiresLocalStaticKeyPair(Role.INITIATOR));
  }

  @Test
  void requiresRemoteEphemeralPublicKey() throws NoSuchPatternException {
    assertTrue(HandshakePattern.getInstance("XXfallback").requiresRemoteEphemeralPublicKey(Role.RESPONDER));
    assertFalse(HandshakePattern.getInstance("XXfallback").requiresRemoteEphemeralPublicKey(Role.INITIATOR));

    assertFalse(HandshakePattern.getInstance("NX").requiresRemoteEphemeralPublicKey(Role.RESPONDER));
    assertFalse(HandshakePattern.getInstance("NX").requiresRemoteEphemeralPublicKey(Role.INITIATOR));
  }

  @Test
  void requiresRemoteStaticPublicKey() throws NoSuchPatternException {
    assertTrue(HandshakePattern.getInstance("NK").requiresRemoteStaticPublicKey(Role.INITIATOR));
    assertFalse(HandshakePattern.getInstance("NK").requiresRemoteStaticPublicKey(Role.RESPONDER));

    assertTrue(HandshakePattern.getInstance("KN").requiresRemoteStaticPublicKey(Role.RESPONDER));
    assertFalse(HandshakePattern.getInstance("KN").requiresRemoteStaticPublicKey(Role.INITIATOR));
  }
}

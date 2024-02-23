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
      final HandshakePattern expectedXXPattern = new HandshakePattern("XX",
          new MessagePattern[0],
          new MessagePattern[]{
              new MessagePattern(Role.INITIATOR, new Token[]{Token.E}),
              new MessagePattern(Role.RESPONDER, new Token[]{Token.E, Token.EE, Token.S, Token.ES}),
              new MessagePattern(Role.INITIATOR, new Token[]{Token.S, Token.SE}),
          });

      assertEquals(expectedXXPattern, HandshakePattern.getInstance("XX"));
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

      assertEquals(expectedKKPattern, HandshakePattern.getInstance("KK"));
    }

    assertThrows(NoSuchPatternException.class,
        () -> HandshakePattern.getInstance("This is not a legitimate Noise handshake pattern"));
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
  void withModifier() throws NoSuchPatternException {
    final HandshakePattern expectedXXFallbackPattern = HandshakePattern.fromString("""
        XXfallback:
          -> e
          ...
          <- e, ee, s, es
          -> s, se
        """);

    assertEquals(expectedXXFallbackPattern,  HandshakePattern.getInstance("XX").withModifier("fallback"));
  }
}

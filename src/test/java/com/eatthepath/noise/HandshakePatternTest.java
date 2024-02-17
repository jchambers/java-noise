package com.eatthepath.noise;

import org.junit.jupiter.api.Test;

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
}
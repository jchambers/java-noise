package com.eatthepath.noise;

public record HandshakePattern(String name, MessagePattern[] preMessagePatterns, MessagePattern[] handshakeMessagePatterns) {

  public record MessagePattern(NoiseHandshake.Role sender, Token[] tokens) {
  }

  public enum Token {
    E,
    S,
    EE,
    ES,
    SE,
    SS;

    static Token fromString(final String string) {
      return switch (string) {
        case "e", "E" -> E;
        case "s", "S" -> S;
        case "ee", "EE" -> EE;
        case "es", "ES" -> ES;
        case "se", "SE" -> SE;
        case "ss", "SS" -> SS;
        default -> throw new IllegalArgumentException("Unrecognized token: " + string);
      };
    }
  }
}

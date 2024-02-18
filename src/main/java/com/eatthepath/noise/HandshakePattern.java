package com.eatthepath.noise;

import java.io.*;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record HandshakePattern(String name, MessagePattern[] preMessagePatterns, MessagePattern[] handshakeMessagePatterns) {

  private static final String HANDSHAKE_PATTERN_FILE_NAME = "handshake-patterns.txt";
  private static final Map<String, HandshakePattern> PATTERNS_BY_NAME = new ConcurrentHashMap<>();

  private static final String PRE_MESSAGE_SEPARATOR = "...";

  public record MessagePattern(NoiseHandshake.Role sender, Token[] tokens) {
    @Override
    public boolean equals(final Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      final MessagePattern that = (MessagePattern) o;
      return sender == that.sender && Arrays.equals(tokens, that.tokens);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(sender);
      result = 31 * result + Arrays.hashCode(tokens);
      return result;
    }
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

  public static HandshakePattern getInstance(final String name) throws NoSuchPatternException {
    final HandshakePattern handshakePattern = PATTERNS_BY_NAME.computeIfAbsent(name, n -> {
      try (final InputStream patternFileInputStream = HandshakePattern.class.getResourceAsStream(HANDSHAKE_PATTERN_FILE_NAME)) {
        if (patternFileInputStream == null) {
          return null;
        }

        try (final BufferedReader reader = new BufferedReader(new InputStreamReader(patternFileInputStream))) {
          final String expectedPatternHeader = name + ":";

          final String patternString = reader.lines()
              .dropWhile(line -> !expectedPatternHeader.equals(line))
              .takeWhile(line -> !line.isBlank())
              .collect(Collectors.joining("\n"));

          if (patternString.isBlank()) {
            return null;
          }

          return fromString(patternString);
        } catch (final IOException e) {
          // This should never happen for a resource file we control
          throw new UncheckedIOException(e);
        }
      } catch (final IOException e) {
        // This should never happen for a resource file we control
        throw new UncheckedIOException(e);
      }
    });

    if (handshakePattern == null) {
      throw new NoSuchPatternException();
    }

    return handshakePattern;
  }

  public static HandshakePattern fromString(final String patternString) {
    final String name = patternString.lines()
        .findFirst()
        .filter(line -> line.endsWith(":"))
        .map(line -> line.substring(0, line.length() - 1))
        .orElseThrow(() -> new IllegalArgumentException("Pattern string did not begin with a name line"));

    final boolean hasPreMessages = patternString.lines()
        .map(String::trim)
        .anyMatch(PRE_MESSAGE_SEPARATOR::equals);

    final MessagePattern[] preMessagePatterns;
    final MessagePattern[] messagePatterns;

    if (hasPreMessages) {
      preMessagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .takeWhile(line -> !PRE_MESSAGE_SEPARATOR.equals(line))
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new HandshakePattern.MessagePattern[0]);

      messagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .dropWhile(line -> !PRE_MESSAGE_SEPARATOR.equals(line))
          // Skip the separator itself
          .skip(1)
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new HandshakePattern.MessagePattern[0]);

    } else {
      preMessagePatterns = new MessagePattern[0];

      messagePatterns = patternString.lines()
          // Skip the name line
          .skip(1)
          .map(String::trim)
          .map(HandshakePattern::messagePatternFromString)
          .toList()
          .toArray(new HandshakePattern.MessagePattern[0]);
    }

    return new HandshakePattern(name, preMessagePatterns, messagePatterns);
  }

  private static MessagePattern messagePatternFromString(final String messagePatternString) {
    final NoiseHandshake.Role sender;

    if (messagePatternString.startsWith("-> ")) {
      sender = NoiseHandshake.Role.INITIATOR;
    } else if (messagePatternString.startsWith("<- ")) {
      sender = NoiseHandshake.Role.RESPONDER;
    } else {
      throw new IllegalArgumentException("Could not identify sender");
    }

    final HandshakePattern.Token[] tokens = Arrays.stream(messagePatternString.substring(3).split(","))
        .map(String::trim)
        .map(HandshakePattern.Token::fromString)
        .toList()
        .toArray(new HandshakePattern.Token[0]);

    return new HandshakePattern.MessagePattern(sender, tokens);
  }

  public boolean requiresLocalStaticKeyPair(final NoiseHandshake.Role role) {
    // The given role needs a local static key pair if any pre-handshake message or handshake message involves that role
    // sending a static key to the other party
    return Stream.concat(Arrays.stream(preMessagePatterns()), Arrays.stream(handshakeMessagePatterns()))
        .filter(messagePattern -> messagePattern.sender() == role)
        .anyMatch(messagePattern -> {
          for (final HandshakePattern.Token token : messagePattern.tokens()) {
            if (token == HandshakePattern.Token.S) {
              return true;
            }
          }

          return false;
        });
  }

  public boolean requiresRemoteStaticPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving a static key
    // from the other party in a pre-handshake message
    return Arrays.stream(preMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .anyMatch(messagePattern -> {
          for (final HandshakePattern.Token token : messagePattern.tokens()) {
            if (token == HandshakePattern.Token.S) {
              return true;
            }
          }

          return false;
        });
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    final HandshakePattern that = (HandshakePattern) o;
    return Objects.equals(name, that.name) && Arrays.equals(preMessagePatterns, that.preMessagePatterns) && Arrays.equals(handshakeMessagePatterns, that.handshakeMessagePatterns);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(name);
    result = 31 * result + Arrays.hashCode(preMessagePatterns);
    result = 31 * result + Arrays.hashCode(handshakeMessagePatterns);
    return result;
  }
}

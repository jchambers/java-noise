package com.eatthepath.noise;

import java.io.*;
import java.util.*;
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
    SS,
    PSK;

    static Token fromString(final String string) {
      return switch (string) {
        case "e", "E" -> E;
        case "s", "S" -> S;
        case "ee", "EE" -> EE;
        case "es", "ES" -> ES;
        case "se", "SE" -> SE;
        case "ss", "SS" -> SS;
        case "psk", "PSK" -> PSK;
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

  static String getFundamentalPatternName(final String fullPatternName) {
    final int fundamentalPatternLength = Math.toIntExact(fullPatternName.chars()
        .takeWhile(c -> c == 'N' || c == 'K' || c == 'X' || c == 'I' || c == '1')
        .count());

    if (fundamentalPatternLength == fullPatternName.length()) {
      return fullPatternName;
    } else if (fundamentalPatternLength > 0) {
      return fullPatternName.substring(0, fundamentalPatternLength);
    }

    throw new IllegalArgumentException("Invalid Noise pattern name: " + fullPatternName);
  }

  static List<String> getModifiers(final String fullPatternName) {
    final String fundamentalPatternName = getFundamentalPatternName(fullPatternName);

    if (fullPatternName.length() == fundamentalPatternName.length()) {
      return Collections.emptyList();
    }

    return Arrays.asList(fullPatternName.substring(fundamentalPatternName.length()).split("\\+"));
  }

  HandshakePattern withModifier(final String modifier) {
    // TODO Disallow duplicate modifiers

    final MessagePattern[] modifiedPreMessagePatterns;
    final MessagePattern[] modifiedHandshakeMessagePatterns;

    if ("fallback".equals(modifier)) {
      // TODO Make sure first handshake message is eligible for fallback
      modifiedPreMessagePatterns = new MessagePattern[preMessagePatterns().length + 1];
      modifiedHandshakeMessagePatterns = new MessagePattern[handshakeMessagePatterns().length - 1];

      System.arraycopy(preMessagePatterns(), 0, modifiedPreMessagePatterns, 0, preMessagePatterns().length);
      modifiedPreMessagePatterns[modifiedPreMessagePatterns.length - 1] = handshakeMessagePatterns()[0];

      System.arraycopy(handshakeMessagePatterns(), 1, modifiedHandshakeMessagePatterns, 0, handshakeMessagePatterns().length - 1);
    } else {
      throw new IllegalArgumentException("Unrecognized modifier: " + modifier);
    }

    final String modifiedName;

    if (name().equals(getFundamentalPatternName(name()))) {
      // Our current name doesn't have any modifiers, and so this is the first
      modifiedName = name() + modifier;
    } else {
      modifiedName = name() + "+" + modifier;
    }

    return new HandshakePattern(modifiedName, modifiedPreMessagePatterns, modifiedHandshakeMessagePatterns);
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

  public boolean isOneWayPattern() {
    return Arrays.stream(handshakeMessagePatterns())
        .allMatch(messagePattern -> messagePattern.sender() == NoiseHandshake.Role.INITIATOR);
  }

  public boolean requiresLocalStaticKeyPair(final NoiseHandshake.Role role) {
    // The given role needs a local static key pair if any pre-handshake message or handshake message involves that role
    // sending a static key to the other party
    return Stream.concat(Arrays.stream(preMessagePatterns()), Arrays.stream(handshakeMessagePatterns()))
        .filter(messagePattern -> messagePattern.sender() == role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  public boolean requiresRemoteStaticPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving a static key
    // from the other party in a pre-handshake message
    return Arrays.stream(preMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  public boolean isPreSharedKeyHandshake() {
    return Arrays.stream(handshakeMessagePatterns())
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.PSK);
  }

  public int getRequiredPreSharedKeyCount() {
    return Math.toIntExact(Arrays.stream(handshakeMessagePatterns())
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .filter(token -> token == Token.PSK)
        .count());
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    } else if (o instanceof final HandshakePattern that) {
      return Objects.equals(name, that.name)
          && Arrays.equals(preMessagePatterns, that.preMessagePatterns)
          && Arrays.equals(handshakeMessagePatterns, that.handshakeMessagePatterns);
    } else {
      return false;
    }
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(name);
    result = 31 * result + Arrays.hashCode(preMessagePatterns);
    result = 31 * result + Arrays.hashCode(handshakeMessagePatterns);
    return result;
  }
}

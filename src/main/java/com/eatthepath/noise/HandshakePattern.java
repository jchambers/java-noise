package com.eatthepath.noise;

import javax.annotation.Nullable;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public record HandshakePattern(String name, MessagePattern[] preMessagePatterns, MessagePattern[] handshakeMessagePatterns) {

  private static final Map<String, HandshakePattern> FUNDAMENTAL_PATTERNS_BY_NAME;

  static {
    try {
      FUNDAMENTAL_PATTERNS_BY_NAME = Collections.unmodifiableMap(
          loadAllFundamentalPatterns("handshake-patterns.txt")
              .collect(Collectors.toMap(HandshakePattern::name, handshakePattern -> handshakePattern)));
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static final Map<String, HandshakePattern> DERIVED_PATTERNS_BY_NAME = new ConcurrentHashMap<>();

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
    if (FUNDAMENTAL_PATTERNS_BY_NAME.containsKey(name)) {
      return FUNDAMENTAL_PATTERNS_BY_NAME.get(name);
    }

    @Nullable final HandshakePattern derivedPattern = DERIVED_PATTERNS_BY_NAME.computeIfAbsent(name, n -> {
      try {
        final String fundamentalPatternName = getFundamentalPatternName(name);

        @Nullable HandshakePattern handshakePattern;

        if (FUNDAMENTAL_PATTERNS_BY_NAME.containsKey(fundamentalPatternName)) {
          handshakePattern = FUNDAMENTAL_PATTERNS_BY_NAME.get(fundamentalPatternName);

          for (final String modifier : getModifiers(name)) {
            handshakePattern = handshakePattern.withModifier(modifier);
          }
        } else {
          handshakePattern = null;
        }

        HandshakePatternValidator.validate(handshakePattern);

        return handshakePattern;
      } catch (final IllegalArgumentException e) {
        return null;
      }
    });

    if (derivedPattern != null) {
      return derivedPattern;
    }

    throw new NoSuchPatternException();
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
    } else if (modifier.startsWith("psk")) {
      final int pskIndex = Integer.parseInt(modifier.substring("psk".length()));

      modifiedPreMessagePatterns = preMessagePatterns().clone();
      modifiedHandshakeMessagePatterns = handshakeMessagePatterns().clone();

      if (pskIndex == 0) {
        // Insert a PSK token at the start of the first message
        final Token[] originalTokens = modifiedHandshakeMessagePatterns[0].tokens();
        final Token[] modifiedTokens = new Token[originalTokens.length + 1];
        modifiedTokens[0] = Token.PSK;
        System.arraycopy(originalTokens, 0, modifiedTokens, 1, originalTokens.length);

        modifiedHandshakeMessagePatterns[0] = new MessagePattern(modifiedHandshakeMessagePatterns[0].sender, modifiedTokens);
      } else {
        // Insert a PSK at the end of the N-1st message
        final Token[] originalTokens = modifiedHandshakeMessagePatterns[pskIndex - 1].tokens();
        final Token[] modifiedTokens = new Token[originalTokens.length + 1];
        modifiedTokens[modifiedTokens.length - 1] = Token.PSK;
        System.arraycopy(originalTokens, 0, modifiedTokens, 0, originalTokens.length);

        modifiedHandshakeMessagePatterns[pskIndex - 1] = new MessagePattern(modifiedHandshakeMessagePatterns[pskIndex - 1].sender, modifiedTokens);
      }
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

  public boolean isFallbackPattern() {
    return getModifiers(name()).contains("fallback");
  }

  public boolean requiresLocalStaticKeyPair(final NoiseHandshake.Role role) {
    // The given role needs a local static key pair if any pre-handshake message or handshake message involves that role
    // sending a static key to the other party
    return Stream.concat(Arrays.stream(preMessagePatterns()), Arrays.stream(handshakeMessagePatterns()))
        .filter(messagePattern -> messagePattern.sender() == role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  public boolean requiresRemoteEphemeralPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving an ephemeral
    // key from the other party in a pre-handshake message
    return Arrays.stream(preMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.E);
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

  private static Stream<HandshakePattern> loadAllFundamentalPatterns(final String handshakeFileName) throws IOException {
    try (final InputStream patternFileInputStream = HandshakePattern.class.getResourceAsStream(handshakeFileName)) {
      if (patternFileInputStream == null) {
        throw new IOException("Fundamental handshake pattern file not found");
      }

      return Arrays.stream(new String(patternFileInputStream.readAllBytes(), StandardCharsets.UTF_8).split("\n\n"))
          .map(String::trim)
          .filter(chunk -> !chunk.isBlank())
          .map(HandshakePattern::fromString);
    }
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

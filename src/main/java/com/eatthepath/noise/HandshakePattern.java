package com.eatthepath.noise;

import javax.annotation.Nullable;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HandshakePattern {

  private final String name;

  private final MessagePattern[] preMessagePatterns;
  private final MessagePattern[] handshakeMessagePatterns;

  private static final Map<String, HandshakePattern> FUNDAMENTAL_PATTERNS_BY_NAME;

  static {
    FUNDAMENTAL_PATTERNS_BY_NAME = Stream.of(
            """
                N:
                  <- s
                  ...
                  -> e, es
                """,

            """
                K:
                  -> s
                  <- s
                  ...
                  -> e, es, ss
                """,

            """
                X:
                  <- s
                  ...
                  -> e, es, s, ss
                """,

            """
                NN:
                  -> e
                  <- e, ee
                """,

            """
                KN:
                  -> s
                  ...
                  -> e
                  <- e, ee, se
                """,

            """
                NK:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                """,

            """
                KK:
                  -> s
                  <- s
                  ...
                  -> e, es, ss
                  <- e, ee, se
                """,

            """
                NX:
                  -> e
                  <- e, ee, s, es
                """,

            """
                KX:
                  -> s
                  ...
                  -> e
                  <- e, ee, se, s, es
                """,

            """
                XN:
                  -> e
                  <- e, ee
                  -> s, se
                """,

            """
                IN:
                  -> e, s
                  <- e, ee, se
                """,

            """
                XK:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> s, se
                """,

            """
                IK:
                  <- s
                  ...
                  -> e, es, s, ss
                  <- e, ee, se
                """,

            """
                XX:
                  -> e
                  <- e, ee, s, es
                  -> s, se
                """,

            """
                IX:
                  -> e, s
                  <- e, ee, se, s, es
                """,

            """
                NK1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                """,

            """
                NX1:
                  -> e
                  <- e, ee, s
                  -> es
                """,

            """
                X1N:
                  -> e
                  <- e, ee
                  -> s
                  <- se
                """,

            """
                X1K:
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> s
                  <- se
                """,

            """
                XK1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> s, se
                """,

            """
                X1K1:
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> s
                  <- se
                """,

            """
                X1X:
                  -> e
                  <- e, ee, s, es
                  -> s
                  <- se
                """,

            """
                XX1:
                  -> e
                  <- e, ee, s
                  -> es, s, se
                """,

            """
                X1X1:
                  -> e
                  <- e, ee, s
                  -> es, s
                  <- se
                """,

            """
                K1N:
                  -> s
                  ...
                  -> e
                  <- e, ee
                  -> se
                """,

            """
                K1K:
                  -> s
                  <- s
                  ...
                  -> e, es
                  <- e, ee
                  -> se
                """,

            """
                KK1:
                  -> s
                  <- s
                  ...
                  -> e
                  <- e, ee, se, es
                """,

            """
                K1K1:
                  -> s
                  <- s
                  ...
                  -> e
                  <- e, ee, es
                  -> se
                """,

            """
                K1X:
                  -> s
                  ...
                  -> e
                  <- e, ee, s, es
                  -> se
                """,

            """
                KX1:
                  -> s
                  ...
                  -> e
                  <- e, ee, se, s
                  -> es
                """,

            """
                K1X1:
                  -> s
                  ...
                  -> e
                  <- e, ee, s
                  -> se, es
                """,

            """
                I1N:
                  -> e, s
                  <- e, ee
                  -> se
                """,

            """
                I1K:
                  <- s
                  ...
                  -> e, es, s
                  <- e, ee
                  -> se
                """,

            """
                IK1:
                  <- s
                  ...
                  -> e, s
                  <- e, ee, se, es
                """,

            """
                I1K1:
                  <- s
                  ...
                  -> e, s
                  <- e, ee, es
                  -> se
                """,

            """
                I1X:
                  -> e, s
                  <- e, ee, s, es
                  -> se
                """,

            """
                IX1:
                  -> e, s
                  <- e, ee, se, s
                  -> es
                """,

            """
                I1X1:
                  -> e, s
                  <- e, ee, s
                  -> se, es
                """)
        .map(HandshakePattern::fromString)
        .collect(Collectors.toMap(HandshakePattern::getName, handshakePattern -> handshakePattern));
  }

  private static final Map<String, HandshakePattern> DERIVED_PATTERNS_BY_NAME = new ConcurrentHashMap<>();

  private static final String PRE_MESSAGE_SEPARATOR = "...";

  HandshakePattern(final String name, final MessagePattern[] preMessagePatterns, final MessagePattern[] handshakeMessagePatterns) {
    this.name = name;

    this.preMessagePatterns = preMessagePatterns;
    this.handshakeMessagePatterns = handshakeMessagePatterns;
  }

  record MessagePattern(NoiseHandshake.Role sender, Token[] tokens) {
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

  enum Token {
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

  public String getName() {
    return name;
  }

  MessagePattern[] getPreMessagePatterns() {
    return preMessagePatterns;
  }

  MessagePattern[] getHandshakeMessagePatterns() {
    return handshakeMessagePatterns;
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
      modifiedPreMessagePatterns = new MessagePattern[getPreMessagePatterns().length + 1];
      modifiedHandshakeMessagePatterns = new MessagePattern[getHandshakeMessagePatterns().length - 1];

      System.arraycopy(getPreMessagePatterns(), 0, modifiedPreMessagePatterns, 0, getPreMessagePatterns().length);
      modifiedPreMessagePatterns[modifiedPreMessagePatterns.length - 1] = getHandshakeMessagePatterns()[0];

      System.arraycopy(getHandshakeMessagePatterns(), 1, modifiedHandshakeMessagePatterns, 0, getHandshakeMessagePatterns().length - 1);
    } else if (modifier.startsWith("psk")) {
      final int pskIndex = Integer.parseInt(modifier.substring("psk".length()));

      modifiedPreMessagePatterns = getPreMessagePatterns().clone();
      modifiedHandshakeMessagePatterns = getHandshakeMessagePatterns().clone();

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

    if (getName().equals(getFundamentalPatternName(getName()))) {
      // Our current name doesn't have any modifiers, and so this is the first
      modifiedName = getName() + modifier;
    } else {
      modifiedName = getName() + "+" + modifier;
    }

    return new HandshakePattern(modifiedName, modifiedPreMessagePatterns, modifiedHandshakeMessagePatterns);
  }

  static HandshakePattern fromString(final String patternString) {
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
    return Arrays.stream(getHandshakeMessagePatterns())
        .allMatch(messagePattern -> messagePattern.sender() == NoiseHandshake.Role.INITIATOR);
  }

  boolean isFallbackPattern() {
    return getModifiers(getName()).contains("fallback");
  }

  public boolean requiresLocalStaticKeyPair(final NoiseHandshake.Role role) {
    // The given role needs a local static key pair if any pre-handshake message or handshake message involves that role
    // sending a static key to the other party
    return Stream.concat(Arrays.stream(getPreMessagePatterns()), Arrays.stream(getHandshakeMessagePatterns()))
        .filter(messagePattern -> messagePattern.sender() == role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  public boolean requiresRemoteEphemeralPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving an ephemeral
    // key from the other party in a pre-handshake message
    return Arrays.stream(getPreMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.E);
  }

  public boolean requiresRemoteStaticPublicKey(final NoiseHandshake.Role role) {
    // The given role needs a remote static key pair if the handshake pattern involves that role receiving a static key
    // from the other party in a pre-handshake message
    return Arrays.stream(getPreMessagePatterns())
        .filter(messagePattern -> messagePattern.sender() != role)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.S);
  }

  boolean isPreSharedKeyHandshake() {
    return Arrays.stream(getHandshakeMessagePatterns())
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == Token.PSK);
  }

  public int getRequiredPreSharedKeyCount() {
    return Math.toIntExact(Arrays.stream(getHandshakeMessagePatterns())
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

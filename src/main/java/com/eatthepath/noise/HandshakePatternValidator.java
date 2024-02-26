package com.eatthepath.noise;

import java.util.*;
import java.util.stream.Stream;

/**
 * A handshake pattern validator checks that a given handshake pattern fulfills all the validation rules specified in
 * <a href="https://noiseprotocol.org/noise.html#handshake-pattern-validity">Section 7.3</a> and
 * <a href="https://noiseprotocol.org/noise.html#validity-rule">Section 9.3</a> of
 * <a href="https://noiseprotocol.org/noise.html">The Noise Protocol Framework</a>.
 */
class HandshakePatternValidator {

  private HandshakePatternValidator() {
  }

  static void validate(final HandshakePattern handshakePattern) {
    validatePublicKeysPresentForKeyAgreement(handshakePattern);
    validateKeyTransmissionLimits(handshakePattern);
    validateKeyAgreementLimits(handshakePattern);
    validateKeyAgreementBeforeEncrypt(handshakePattern);
    validatePreSharedKeyEphemeralKey(handshakePattern);
  }

  static void validatePublicKeysPresentForKeyAgreement(final HandshakePattern handshakePattern) {
    // "1. Parties can only perform DH between private keys and public keys they possess."

    for (final NoiseHandshake.Role role : NoiseHandshake.Role.values()) {
      boolean hasRemoteStaticKey = false;
      boolean hasRemoteEphemeralKey = false;

      for (final HandshakePattern.MessagePattern messagePattern : handshakePattern.preMessagePatterns()) {
        if (messagePattern.sender() != role) {
          for (final HandshakePattern.Token token : messagePattern.tokens()) {
            switch (token) {
              case E -> hasRemoteEphemeralKey = true;
              case S -> hasRemoteStaticKey = true;
              default -> throw new IllegalArgumentException("Pre-handshake messages may not contain key agreement tokens");
            }
          }
        }
      }

      for (final HandshakePattern.MessagePattern messagePattern : handshakePattern.handshakeMessagePatterns()) {
        for (HandshakePattern.Token token : messagePattern.tokens()) {
          switch (token) {
            case E -> {
              if (messagePattern.sender() != role) {
                hasRemoteEphemeralKey = true;
              }
            }

            case S -> {
              if (messagePattern.sender() != role) {
                hasRemoteStaticKey = true;
              }
            }

            case EE -> {
              if (!hasRemoteEphemeralKey) {
                throw new IllegalArgumentException("Pattern contains an EE token, but no remote ephemeral key available for " + role);
              }
            }

            case SS -> {
              if (!hasRemoteStaticKey) {
                throw new IllegalArgumentException("Pattern contains an SS token, but no remote static key available for " + role);
              }
            }

            case ES -> {
              // Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder.
              switch (role) {
                case INITIATOR -> {
                  if (!hasRemoteStaticKey) {
                    throw new IllegalArgumentException("Pattern contains an ES token, but no remote static key available for " + role);
                  }
                }
                case RESPONDER -> {
                  if (!hasRemoteEphemeralKey) {
                    throw new IllegalArgumentException("Pattern contains an ES token, but no remote ephemeral key available for " + role);
                  }
                }
              }
            }

            case SE -> {
              // Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder.
              switch (role) {
                case INITIATOR -> {
                  if (!hasRemoteEphemeralKey) {
                    throw new IllegalArgumentException("Pattern contains an SE token, but no remote ephemeral key available for " + role);
                  }
                }
                case RESPONDER -> {
                  if (!hasRemoteStaticKey) {
                    throw new IllegalArgumentException("Pattern contains an SE token, but no remote static key available for " + role);
                  }
                }
              }
            }

            default -> {}
          }
        }
      }
    }
  }

  static void validateKeyTransmissionLimits(final HandshakePattern handshakePattern) {
    // "2. Parties must not send their static public key or ephemeral public key more than once per handshake (i.e.
    // including the pre-messages, there must be no more than one occurrence of 'e', and one occurrence of 's', in the
    // messages sent by any party)."
    for (final NoiseHandshake.Role role : NoiseHandshake.Role.values()) {
      for (final HandshakePattern.Token token : new HandshakePattern.Token[] { HandshakePattern.Token.E, HandshakePattern.Token.S }) {
        final long tokenCount =
            Stream.concat(Arrays.stream(handshakePattern.preMessagePatterns()), Arrays.stream(handshakePattern.handshakeMessagePatterns()))
                .filter(messagePattern -> messagePattern.sender() == role)
                .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
                .filter(t -> t == token)
                .count();

        if (tokenCount > 1) {
          throw new IllegalArgumentException(role + " has more than one " + token + " token in pattern");
        }
      }
    }
  }

  static void validateKeyAgreementLimits(final HandshakePattern handshakePattern) {
    // "3. Parties must not perform a DH calculation more than once per handshake (i.e. there must be no more than one
    // occurrence of 'ee', 'es', 'se', or 'ss' per handshake)."
    for (final HandshakePattern.Token token : new HandshakePattern.Token[]{
        HandshakePattern.Token.EE, HandshakePattern.Token.ES, HandshakePattern.Token.SE, HandshakePattern.Token.SS
    }) {

      final long tokenCount = Arrays.stream(handshakePattern.handshakeMessagePatterns())
          .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
          .filter(t -> t == token)
          .count();

      if (tokenCount > 1) {
        throw new IllegalArgumentException("Key agreement token " + token + " appears more than once in pattern");
      }
    }
  }

  static void validateKeyAgreementBeforeEncrypt(final HandshakePattern handshakePattern) {
    // "4. After performing a DH between a remote public key (either static or ephemeral) and the local static key, the
    // local party must not call ENCRYPT() unless it has also performed a DH between its local ephemeral key and the
    // remote public key."
    final Set<HandshakePattern.Token> encounteredTokens = new HashSet<>();
    final EnumMap<NoiseHandshake.Role, Set<HandshakePattern.Token>> requiredTokensByRole = new EnumMap<>(NoiseHandshake.Role.class);

    for (final HandshakePattern.MessagePattern messagePattern : handshakePattern.handshakeMessagePatterns()) {
      for (final HandshakePattern.Token token : messagePattern.tokens()) {
        encounteredTokens.add(token);

        switch (token) {
          case ES -> requiredTokensByRole.computeIfAbsent(NoiseHandshake.Role.RESPONDER, ignored -> new HashSet<>())
              .add(HandshakePattern.Token.EE);

          case SE -> requiredTokensByRole.computeIfAbsent(NoiseHandshake.Role.INITIATOR, ignored -> new HashSet<>())
              .add(HandshakePattern.Token.EE);

          case SS -> {
            requiredTokensByRole.computeIfAbsent(NoiseHandshake.Role.INITIATOR, ignored -> new HashSet<>())
                .add(HandshakePattern.Token.ES);

            requiredTokensByRole.computeIfAbsent(NoiseHandshake.Role.RESPONDER, ignored -> new HashSet<>())
                .add(HandshakePattern.Token.SE);
          }
          default -> {}
        }
      }

      for (final HandshakePattern.Token requiredToken : requiredTokensByRole.getOrDefault(messagePattern.sender(), Collections.emptySet())) {
        if (!encounteredTokens.contains(requiredToken)) {
          throw new IllegalArgumentException("Handshake pattern calls for encryption before performing key agreement between local ephemeral and remote public key for " + messagePattern.sender());
        }
      }
    }
  }

  static void validatePreSharedKeyEphemeralKey(final HandshakePattern handshakePattern) {
    for (final NoiseHandshake.Role role : NoiseHandshake.Role.values()) {
      boolean hasSentEphemeralKey = Arrays.stream(handshakePattern.preMessagePatterns())
          .filter(messagePattern -> messagePattern.sender() == role)
          .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
          .anyMatch(token -> token == HandshakePattern.Token.E);

      boolean needsEphemeralKey = false;

      for (final HandshakePattern.MessagePattern messagePattern : handshakePattern.handshakeMessagePatterns()) {
        for (final HandshakePattern.Token token : messagePattern.tokens()) {
          if (token == HandshakePattern.Token.PSK) {
            needsEphemeralKey = true;
          }

          if (token == HandshakePattern.Token.E && messagePattern.sender() == role) {
            hasSentEphemeralKey = true;
          }
        }

        if (messagePattern.sender() == role && needsEphemeralKey && !hasSentEphemeralKey) {
          throw new IllegalArgumentException(role + " does not send ephemeral key before sending message after processing a PSK");
        }
      }
    }
  }
}

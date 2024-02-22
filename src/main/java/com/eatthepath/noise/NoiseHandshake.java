package com.eatthepath.noise;

import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.ShortBufferException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class NoiseHandshake {

  private final String noiseProtocolName;
  private final HandshakePattern handshakePattern;
  private final Role role;

  private int currentMessagePattern = 0;

  private final CipherState cipherState;
  private final NoiseHash noiseHash;
  private final NoiseKeyAgreement keyAgreement;

  private final byte[] chainingKey;
  private final byte[] hash;

  @Nullable
  private KeyPair localEphemeralKeyPair;

  @Nullable
  private PublicKey remoteEphemeralPublicKey;

  @Nullable
  private final KeyPair localStaticKeyPair;

  @Nullable
  private PublicKey remoteStaticPublicKey;

  @Nullable
  private final List<byte[]> preSharedKeys;

  private int currentPreSharedKey;

  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  public enum Role {
    INITIATOR,
    RESPONDER
  }

  public NoiseHandshake(final Role role,
                        final HandshakePattern handshakePattern,
                        final NoiseKeyAgreement keyAgreement,
                        final NoiseCipher noiseCipher,
                        final NoiseHash noiseHash,
                        @Nullable final byte[] prologue,
                        @Nullable final KeyPair localStaticKeyPair,
                        @Nullable final KeyPair localEphemeralKeyPair,
                        @Nullable final PublicKey remoteStaticPublicKey,
                        @Nullable final PublicKey remoteEphemeralPublicKey,
                        @Nullable final List<byte[]> preSharedKeys) {

    this.handshakePattern = handshakePattern;
    this.role = role;

    this.cipherState = new CipherState(noiseCipher);
    this.noiseHash = noiseHash;
    this.keyAgreement = keyAgreement;

    if (handshakePattern.requiresLocalStaticKeyPair(role)) {
      if (localStaticKeyPair == null) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern requires a local static key pair for " + role + " role");
      }
    } else {
      if (localStaticKeyPair != null) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern does not allow a local static key pair for " + role + " role");
      }
    }

    if (handshakePattern.requiresRemoteStaticPublicKey(role)) {
      if (remoteStaticPublicKey == null) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern requires a remote static public key for " + role + " role");
      }
    } else {
      if (remoteStaticPublicKey != null) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern does not allow a remote static public key for " + role + " role");
      }
    }

    final int requiredPreSharedKeys = handshakePattern.getRequiredPreSharedKeyCount();

    if (requiredPreSharedKeys > 0) {
      if (preSharedKeys == null || preSharedKeys.size() != requiredPreSharedKeys) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern requires " + requiredPreSharedKeys + " pre-shared keys");
      }

      if (preSharedKeys.stream().anyMatch(preSharedKey -> preSharedKey.length != 32)) {
        throw new IllegalArgumentException("Pre-shared keys must be exactly 32 bytes");
      }
    } else {
      if (preSharedKeys != null && !preSharedKeys.isEmpty()) {
        throw new IllegalArgumentException(handshakePattern.name() + " handshake pattern does not allow pre-shared keys");
      }
    }

    // TODO Validate key compatibility
    this.localStaticKeyPair = localStaticKeyPair;
    this.localEphemeralKeyPair = localEphemeralKeyPair;
    this.remoteStaticPublicKey = remoteStaticPublicKey;
    this.remoteEphemeralPublicKey = remoteEphemeralPublicKey;
    this.preSharedKeys = preSharedKeys;

    this.noiseProtocolName = "Noise_" +
        handshakePattern.name() + "_" +
        keyAgreement.getName() + "_" +
        noiseCipher.getName() + "_" +
        noiseHash.getName();

    hash = new byte[noiseHash.getHashLength()];

    final byte[] protocolNameBytes = noiseProtocolName.getBytes(StandardCharsets.UTF_8);

    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    if (protocolNameBytes.length <= messageDigest.getDigestLength()) {
      System.arraycopy(protocolNameBytes, 0, hash, 0, protocolNameBytes.length);
    } else {
      try {
        messageDigest.reset();
        messageDigest.update(protocolNameBytes);
        messageDigest.digest(hash, 0, hash.length);
      } catch (final DigestException e) {
        // This should never happen
        throw new AssertionError(e);
      }
    }

    chainingKey = hash.clone();
    mixHash(prologue != null ? prologue : EMPTY_BYTE_ARRAY);

    Arrays.stream(handshakePattern.preMessagePatterns())
        // Process the initiator's keys first; "initiator" comes before "responder" in the `Role` enum, and so we don't
        // need a specialized comparator
        .sorted(Comparator.comparing(HandshakePattern.MessagePattern::sender))
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens())
            .map(token -> switch (token) {
              case E -> {
                final PublicKey ephemeralPublicKey;

                if (messagePattern.sender() == role) {
                  ephemeralPublicKey = localEphemeralKeyPair != null ? localEphemeralKeyPair.getPublic() : null;
                } else {
                  ephemeralPublicKey = remoteEphemeralPublicKey;
                }

                if (ephemeralPublicKey == null) {
                  throw new IllegalStateException("Ephemeral public key for " + messagePattern.sender() + " role must not be null");
                }

                yield ephemeralPublicKey;
              }
              case S -> {
                final PublicKey staticPublicKey;

                if (messagePattern.sender() == role) {
                  staticPublicKey = localStaticKeyPair != null ? localStaticKeyPair.getPublic() : null;
                } else {
                  staticPublicKey = remoteStaticPublicKey;
                }

                if (staticPublicKey == null) {
                  throw new IllegalStateException("Static public key for " + messagePattern.sender() + " role must not be null");
                }

                yield staticPublicKey;
              }
              case EE, ES, SE, SS, PSK ->
                  throw new IllegalArgumentException("Key-mixing tokens must not appear in pre-messages");
            }))
        .forEach(publicKey -> {
          final byte[] publicKeyBytes = keyAgreement.serializePublicKey(publicKey);
          mixHash(publicKeyBytes);
        });
  }

  public String getNoiseProtocolName() {
    return noiseProtocolName;
  }

  private void mixKey(final byte[] inputKeyMaterial) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, inputKeyMaterial, 2);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    cipherState.setKey(derivedKeys[1]);
  }

  private void mixHash(final byte[] bytes) {
    mixHash(bytes, 0, bytes.length);
  }

  private void mixHash(final byte[] bytes, final int offset, final int length) {
    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.update(bytes, offset, length);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private void mixKeyAndHash(final byte[] preSharedKey) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, preSharedKey, 3);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);
    mixHash(derivedKeys[1]);
    cipherState.setKey(derivedKeys[2]);
  }

  private int encryptAndHash(final byte[] plaintext,
                             final int plaintextOffset,
                             final int plaintextLength,
                             final byte[] ciphertext,
                             final int ciphertextOffset) throws ShortBufferException {

    final int ciphertextLength =
        cipherState.encrypt(hash, 0, hash.length, plaintext, plaintextOffset, plaintextLength, ciphertext, ciphertextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return ciphertextLength;
  }

  private int decryptAndHash(final byte[] ciphertext,
                             final int ciphertextOffset,
                             final int ciphertextLength,
                             final byte[] plaintext,
                             final int plaintextOffset) throws ShortBufferException, AEADBadTagException {

    final int plaintextLength =
        cipherState.decrypt(hash, 0, hash.length, ciphertext, ciphertextOffset, ciphertextLength, plaintext, plaintextOffset);

    mixHash(ciphertext, ciphertextOffset, ciphertextLength);

    return plaintextLength;
  }

  public boolean isExpectingRead() {
    if (currentMessagePattern < handshakePattern.handshakeMessagePatterns().length) {
      return handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() != role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  public boolean isExpectingWrite() {
    if (currentMessagePattern < handshakePattern.handshakeMessagePatterns().length) {
      return handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() == role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
  }

  public boolean isDone() {
    return currentMessagePattern == handshakePattern.handshakeMessagePatterns().length;
  }

  public int getOutboundMessageLength(final int payloadLength) {
    if (handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() != role) {
      throw new IllegalArgumentException("Handshake is not currently expecting to send a message");
    }

    return getOutboundMessageLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), payloadLength);
  }

  // Visible for testing
  static int getOutboundMessageLength(final HandshakePattern handshakePattern,
                                      final int message,
                                      final int publicKeyLength,
                                      final int payloadLength) {

    if (message < 0 || message >= handshakePattern.handshakeMessagePatterns().length) {
      throw new IndexOutOfBoundsException(
          String.format("Message index must be between 0 and %d for this handshake pattern, but was %d",
              handshakePattern.handshakeMessagePatterns().length, message));
    }

    final boolean isPreSharedKeyHandshake = handshakePattern.isPreSharedKeyHandshake();

    // Run through all of this handshake's message patterns to see if we have a key prior to reaching the message of
    // interest
    boolean hasKey = Arrays.stream(handshakePattern.handshakeMessagePatterns())
        .limit(message)
        .flatMap(messagePattern -> Arrays.stream(messagePattern.tokens()))
        .anyMatch(token -> token == HandshakePattern.Token.EE
            || token == HandshakePattern.Token.ES
            || token == HandshakePattern.Token.SE
            || token == HandshakePattern.Token.SS
            || token == HandshakePattern.Token.PSK
            || (token == HandshakePattern.Token.E && isPreSharedKeyHandshake));

    int messageLength = 0;

    for (final HandshakePattern.Token token : handshakePattern.handshakeMessagePatterns()[message].tokens()) {
      switch (token) {
        case E -> {
          messageLength += publicKeyLength;

          if (isPreSharedKeyHandshake) {
            hasKey = true;
          }
        }
        case S -> {
          messageLength += publicKeyLength;

          if (hasKey) {
            // If we have a key, then the static key is encrypted and has a 16-byte AEAD tag
            messageLength += 16;
          }
        }
        case EE, ES, SE, SS, PSK -> hasKey = true;
      }
    }

    messageLength += payloadLength;

    if (hasKey) {
      // If we have a key, then the payload is encrypted and has a 16-byte AEAD tag
      messageLength += 16;
    }

    return messageLength;
  }

  public int getPayloadLength(final int ciphertextLength) {
    return getPayloadLength(handshakePattern, currentMessagePattern, keyAgreement.getPublicKeyLength(), ciphertextLength);
  }

  static int getPayloadLength(final HandshakePattern handshakePattern,
                              final int message,
                              final int publicKeyLength,
                              final int ciphertextLength) {

    final int emptyPayloadMessageLength = getOutboundMessageLength(handshakePattern, message, publicKeyLength, 0);

    if (ciphertextLength < emptyPayloadMessageLength) {
      throw new IllegalArgumentException("Ciphertext is shorter than minimum expected message length");
    }

    return ciphertextLength - emptyPayloadMessageLength;
  }

  public byte[] writeMessage(@Nullable final byte[] payload) {
    // TODO Verify that message size is within bounds
    final int payloadLength = payload != null ? payload.length : 0;
    final byte[] message = new byte[getOutboundMessageLength(payloadLength)];

    try {
      final int messageLength = writeMessage(message, 0, payload, 0, payloadLength);
      assert message.length == messageLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return message;
  }

  public int writeMessage(final byte[] message,
                          final int messageOffset,
                          @Nullable final byte[] payload,
                          final int payloadOffset,
                          final int payloadLength) throws ShortBufferException {

    // TODO Check message buffer length?

    if (!isExpectingWrite()) {
      throw new IllegalStateException("Handshake not currently expecting to write a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.handshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          // Ephemeral keys may be specified in advance for "fallback" patterns and for testing, and so may not
          // necessarily be null at this point.
          if (localEphemeralKeyPair == null) {
            localEphemeralKeyPair = keyAgreement.generateKeyPair();
          }

          final byte[] ephemeralKeyBytes = keyAgreement.serializePublicKey(localEphemeralKeyPair.getPublic());
          System.arraycopy(ephemeralKeyBytes, 0, message, offset, keyAgreement.getPublicKeyLength());

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += keyAgreement.getPublicKeyLength();
        }

        case S -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static public key available");
          }

          try {
            offset += encryptAndHash(keyAgreement.serializePublicKey(localStaticKeyPair.getPublic()), 0, keyAgreement.getPublicKeyLength(),
                message, offset);
          } catch (final ShortBufferException e) {
            // This should never happen for buffers we control
            throw new AssertionError("Short buffer for static key component", e);
          }
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    if (payload != null) {
      offset += encryptAndHash(payload, payloadOffset, payloadLength, message, offset);
    } else {
      offset += encryptAndHash(EMPTY_BYTE_ARRAY, 0, 0, message, offset);
    }

    currentMessagePattern += 1;

    return offset;
  }

  public byte[] readMessage(final byte[] message) throws InvalidKeySpecException, AEADBadTagException {
    final byte[] payload = new byte[getPayloadLength(message.length)];

    try {
      final int payloadLength = readMessage(message, 0, message.length, payload, 0);
      assert payload.length == payloadLength;
    } catch (final ShortBufferException e) {
      // This should never happen for a buffer we control
      throw new AssertionError(e);
    }

    return payload;
  }

  public int readMessage(final byte[] message,
                         final int messageOffset,
                         final int messageLength,
                         final byte[] payload,
                         final int payloadOffset) throws InvalidKeySpecException, ShortBufferException, AEADBadTagException {

    if (!isExpectingRead()) {
      throw new IllegalStateException("Handshake not currently expecting to read a message");
    }

    int offset = messageOffset;

    final HandshakePattern.MessagePattern messagePattern =
        handshakePattern.handshakeMessagePatterns()[currentMessagePattern];

    for (final HandshakePattern.Token token : messagePattern.tokens()) {
      switch (token) {
        case E -> {
          if (remoteEphemeralPublicKey != null) {
            throw new IllegalStateException("Remote ephemeral key already set");
          }

          final byte[] ephemeralKeyBytes = new byte[keyAgreement.getPublicKeyLength()];
          System.arraycopy(message, offset, ephemeralKeyBytes, 0, ephemeralKeyBytes.length);

          remoteEphemeralPublicKey = keyAgreement.deserializePublicKey(ephemeralKeyBytes);

          mixHash(ephemeralKeyBytes);

          if (handshakePattern.isPreSharedKeyHandshake()) {
            mixKey(ephemeralKeyBytes);
          }

          offset += ephemeralKeyBytes.length;
        }

        case S -> {
          if (remoteStaticPublicKey != null) {
            throw new IllegalStateException("Remote static key already set");
          }

          final int staticKeyCiphertextLength = keyAgreement.getPublicKeyLength() + (cipherState.hasKey() ? 16 : 0);
          final byte[] staticKeyBytes = new byte[keyAgreement.getPublicKeyLength()];

          decryptAndHash(message, offset, staticKeyCiphertextLength, staticKeyBytes, 0);

          remoteStaticPublicKey = keyAgreement.deserializePublicKey(staticKeyBytes);

          offset += staticKeyCiphertextLength;
        }

        case EE, ES, SE, SS, PSK -> handleMixKeyToken(token);
      }
    }

    currentMessagePattern += 1;

    return decryptAndHash(message, offset, messageLength - offset, payload, payloadOffset);
  }

  private void handleMixKeyToken(final HandshakePattern.Token token) {
    try {
      switch (token) {
        case EE -> {
          if (localEphemeralKeyPair == null) {
            throw new IllegalStateException("No local ephemeral key available");
          }

          if (remoteEphemeralPublicKey == null) {
            throw new IllegalStateException("No remote ephemeral key available");
          }

          mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteEphemeralPublicKey));
        }

        case ES -> {
          switch (role) {
            case INITIATOR -> {
              if (localEphemeralKeyPair == null) {
                throw new IllegalStateException("No local ephemeral key available");
              }

              if (remoteStaticPublicKey == null) {
                throw new IllegalStateException("No remote static key available");
              }

              mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
            }
            case RESPONDER -> {
              if (localStaticKeyPair == null) {
                throw new IllegalStateException("No local static key available");
              }

              if (remoteEphemeralPublicKey == null) {
                throw new IllegalStateException("No remote ephemeral key available");
              }

              mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
            }
          }
        }

        case SE -> {
          switch (role) {
            case INITIATOR -> {
              if (localStaticKeyPair == null) {
                throw new IllegalStateException("No local static key available");
              }

              if (remoteEphemeralPublicKey == null) {
                throw new IllegalStateException("No remote ephemeral key available");
              }

              mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteEphemeralPublicKey));
            }
            case RESPONDER -> {
              if (localEphemeralKeyPair == null) {
                throw new IllegalStateException("No local ephemeral key available");
              }

              if (remoteStaticPublicKey == null) {
                throw new IllegalStateException("No remote static key available");
              }

              mixKey(keyAgreement.generateSecret(localEphemeralKeyPair.getPrivate(), remoteStaticPublicKey));
            }
          }
        }

        case SS -> {
          if (localStaticKeyPair == null) {
            throw new IllegalStateException("No local static key available");
          }

          if (remoteStaticPublicKey == null) {
            throw new IllegalStateException("No remote static key available");
          }

          mixKey(keyAgreement.generateSecret(localStaticKeyPair.getPrivate(), remoteStaticPublicKey));
        }

        case PSK -> {
          if (preSharedKeys == null || currentPreSharedKey >= preSharedKeys.size()) {
            throw new IllegalStateException("No pre-shared key available");
          }

          mixKeyAndHash(preSharedKeys.get(currentPreSharedKey++));
        }

        default -> throw new IllegalArgumentException("Unexpected key-mixing token: " + token.name());
      }
    } catch (final InvalidKeyException e) {
      // This should never happen. All keys have been parsed and validated either at construction time or upon arrival
      // from the other party.
      throw new AssertionError(e);
    }
  }

  public NoiseTransport toTransport() {
    if (!isDone()) {
      throw new IllegalStateException("Handshake is not finished and expects to exchange more messages");
    }

    if (handshakePattern.isOneWayPattern()) {
      // TODO Explain
      throw new IllegalStateException();
    }

    return split();
  }

  public NoiseTransportReader toTransportReader() {
    if (!handshakePattern.isOneWayPattern()) {
      // TODO Explain
      throw new IllegalStateException();
    }

    if (role != Role.INITIATOR) {
      // TODO Explain
      throw new IllegalStateException();
    }

    return split();
  }

  public NoiseTransportWriter toTransportWriter() {
    if (!handshakePattern.isOneWayPattern()) {
      // TODO Explain
      throw new IllegalStateException();
    }

    if (role != Role.INITIATOR) {
      // TODO Explain
      throw new IllegalStateException();
    }

    return split();
  }

  private NoiseTransportImpl split() {
    if (!isDone()) {
      throw new IllegalStateException("Handshake is not finished and expects to exchange more messages");
    }

    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, EMPTY_BYTE_ARRAY, 2);

    final CipherState readerCipherState = new CipherState(cipherState.getCipher());
    readerCipherState.setKey(derivedKeys[role == Role.INITIATOR ? 1 : 0]);

    final CipherState writerCipherState = new CipherState(cipherState.getCipher());
    writerCipherState.setKey(derivedKeys[role == Role.INITIATOR ? 0 : 1]);

    return new NoiseTransportImpl(readerCipherState, writerCipherState);
  }
}

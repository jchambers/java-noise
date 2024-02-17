package com.eatthepath.noise;

import javax.annotation.Nullable;
import javax.crypto.AEADBadTagException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;

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
  private KeyPair localStaticKeyPair;

  @Nullable
  private PublicKey remoteStaticPublicKey;

  public enum Role {
    INITIATOR,
    RESPONDER
  }

  public NoiseHandshake(final String noiseProtocolName,
                        final HandshakePattern handshakePattern,
                        final Role role,
                        final CipherState cipherState,
                        final NoiseHash noiseHash,
                        final NoiseKeyAgreement keyAgreement,
                        @Nullable final byte[] prologue,
                        @Nullable final KeyPair localStaticKeyPair,
                        @Nullable final KeyPair localEphemeralKeyPair,
                        @Nullable final PublicKey remoteStaticPublicKey,
                        @Nullable final PublicKey remoteEphemeralPublicKey) {

    this.noiseProtocolName = noiseProtocolName;
    this.handshakePattern = handshakePattern;
    this.role = role;

    this.cipherState = cipherState;
    this.noiseHash = noiseHash;
    this.keyAgreement = keyAgreement;

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
  }

  private void mixKey(final byte[] inputKeyMaterial) {
    final byte[][] derivedKeys = noiseHash.deriveKeys(chainingKey, inputKeyMaterial, 2);

    System.arraycopy(derivedKeys[0], 0, chainingKey, 0, derivedKeys[0].length);

    // TODO Truncate to 32 bytes
    cipherState.setKey(new SecretKeySpec(derivedKeys[1], "RAW"));
  }

  private void mixHash(final byte[] bytes) {
    final MessageDigest messageDigest = noiseHash.getMessageDigest();

    try {
      messageDigest.reset();
      messageDigest.update(hash);
      messageDigest.update(bytes);
      messageDigest.digest(hash, 0, hash.length);
    } catch (final DigestException e) {
      // This should never happen
      throw new AssertionError(e);
    }
  }

  private byte[] encryptAndHash(final byte[] plaintext) {
    final byte[] ciphertext = cipherState.encrypt(hash, plaintext);
    mixHash(ciphertext);

    return ciphertext;
  }

  private byte[] decryptAndHash(final byte[] ciphertext) throws AEADBadTagException {
    final byte[] plaintext = cipherState.decrypt(hash, ciphertext);
    mixHash(ciphertext);

    return plaintext;
  }

  private boolean expectingRead() {
    if (currentMessagePattern < handshakePattern.handshakeMessagePatterns().length) {
      return handshakePattern.handshakeMessagePatterns()[currentMessagePattern].sender() != role;
    }

    // We've completed the whole handshake, so we're not expecting any more messages
    return false;
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

    boolean hasKey = false;

    // Run through all of this handshake's message patterns to see if we have a key prior to reaching the message of
    // interest
    for (int i = 0; i < message; i++) {
      for (final HandshakePattern.Token token : handshakePattern.handshakeMessagePatterns()[i].tokens()) {
        switch (token) {
          case EE, ES, SE, SS -> hasKey = true;
          default -> {}
        }
      }

      // No need to analyze additional message patterns if we already know we have a key
      if (hasKey) {
        break;
      }
    }

    int messageLength = 0;

    for (final HandshakePattern.Token token : handshakePattern.handshakeMessagePatterns()[message].tokens()) {
      switch (token) {
        case E -> messageLength += publicKeyLength;
        case S -> {
          messageLength += publicKeyLength;

          if (hasKey) {
            // If we have a key, then the static key is encrypted and has a 16-byte AEAD tag
            messageLength += 16;
          }
        }
        case EE, ES, SE, SS -> hasKey = true;
      }
    }

    messageLength += payloadLength;

    if (hasKey) {
      // If we have a key, then the payload is encrypted and has a 16-byte AEAD tag
      messageLength += 16;
    }

    return messageLength;
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
}

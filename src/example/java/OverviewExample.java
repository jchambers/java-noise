import com.eatthepath.noise.NoiseHandshake;
import com.eatthepath.noise.NoiseHandshakeBuilder;
import com.eatthepath.noise.NoiseTransport;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@SuppressWarnings("NewClassNamingConvention")
public class OverviewExample {

  @Test
  void transport() throws NoSuchAlgorithmException, InvalidKeySpecException, AEADBadTagException {
    final NoiseHandshake initiatorHandshake = NoiseHandshakeBuilder.forNNInitiator()
        .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
        .build();

    final NoiseHandshake responderHandshake = NoiseHandshakeBuilder.forNNResponder()
        .setComponentsFromProtocolName("Noise_NN_25519_AESGCM_SHA256")
        .build();

    responderHandshake.readMessage(initiatorHandshake.writeMessage(null));
    initiatorHandshake.readMessage(responderHandshake.writeMessage(null));

    // @start region="transport-messages"
    final NoiseTransport initiatorTransport = initiatorHandshake.toTransport();
    final NoiseTransport responderTransport = responderHandshake.toTransport();

    final byte[] originalPlaintextBytes = "Hello, Bob!".getBytes(StandardCharsets.UTF_8);

    final byte[] aliceToBobCiphertext =
        initiatorTransport.writeMessage(originalPlaintextBytes);

    assert !Arrays.equals(aliceToBobCiphertext, originalPlaintextBytes);

    final byte[] aliceToBobPlaintext = responderTransport.readMessage(aliceToBobCiphertext);

    assert Arrays.equals(aliceToBobPlaintext, originalPlaintextBytes);
    // @end
  }
}

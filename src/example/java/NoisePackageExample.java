import com.eatthepath.noise.NamedProtocolHandshakeBuilder;
import com.eatthepath.noise.NoSuchPatternException;
import com.eatthepath.noise.NoiseHandshake;
import com.eatthepath.noise.NoiseTransport;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

@SuppressWarnings("NewClassNamingConvention")
public class NoisePackageExample {

  @Test
  void simpleHandshake() throws NoSuchAlgorithmException, NoSuchPatternException, InvalidKeySpecException, AEADBadTagException {
    // @start region="build-handshake"
    final String noiseProtocolName = "Noise_NN_25519_ChaChaPoly_SHA256";

    final NoiseHandshake initiatorHandshake =
        new NamedProtocolHandshakeBuilder(noiseProtocolName, NoiseHandshake.Role.INITIATOR).build();

    final NoiseHandshake responderHandshake =
        new NamedProtocolHandshakeBuilder(noiseProtocolName, NoiseHandshake.Role.RESPONDER).build();
    // @end

    // @start region="handshake-messages"
    // -> e (with no additional payload)
    final byte[] eMessage = initiatorHandshake.writeMessage(null);
    responderHandshake.readMessage(eMessage);

    // <- e, ee (with no additional payload)
    final byte[] eEeMessage = responderHandshake.writeMessage(null);
    initiatorHandshake.readMessage(eEeMessage);

    // At this point, the handshake is finished, and we can "split" the handshake into a Noise transport
    assert initiatorHandshake.isDone();
    assert responderHandshake.isDone();
    // @end

    // @start region="transport-messages"
    final NoiseTransport initiatorTransport = initiatorHandshake.toTransport();
    final NoiseTransport responderTransport = responderHandshake.toTransport();

    final byte[] plaintext = "Hello, world!".getBytes(StandardCharsets.UTF_8);
    final byte[] ciphertext = initiatorTransport.writeMessage(plaintext);

    final byte[] decryptedPlaintext = responderTransport.readMessage(ciphertext);

    assert Arrays.equals(plaintext, decryptedPlaintext);
    // @end
  }
}

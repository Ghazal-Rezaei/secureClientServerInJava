import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;


public class SecureInputStream extends InputStream {

  private Cipher cipher;
  private InputStream in;

  public SecureInputStream(Cipher c, InputStream is){
    this.cipher = c;
    this.in = is;
  }

  public int read()
         throws IOException {
    return in.read();
  }

  public byte[] integrityCheck(ByteArrayOutputStream baos) {
    byte[] temp = baos.toByteArray();
    baos.reset();

    if(temp.length > 28) {
      byte[] ciphertext = new byte[temp.length-8];
      byte[] IV = new byte[8];
      System.arraycopy(temp, 0, ciphertext, 0, ciphertext.length);
      System.arraycopy(temp, ciphertext.length, IV, 0, IV.length);
   
      byte[] packet = trim(cipher.decryptCFB(ciphertext,IV));

      byte[] message = new byte[packet.length-20];
      byte[] messageHash = new byte[20];
      System.arraycopy(packet, 0, message, 0, message.length);
      System.arraycopy(packet, message.length, messageHash, 0, messageHash.length);

      HashFunction hf = new HashFunction();
      hf.update(message);
      byte[] hashResult = hf.digest();

      if(Arrays.equals(hashResult, messageHash)) return message;
      else return "Message has been distorted!".getBytes();	
    }
    
    return "\n".getBytes();
  }

  private byte[] trim(byte[] bytes) {
   int i = bytes.length - 1;
   while (i >= 0 && bytes[i] == 0) {
      --i;
   }
   return Arrays.copyOf(bytes, i + 1);
  }

  public void close()
           throws IOException {
    in.close();
  }
}
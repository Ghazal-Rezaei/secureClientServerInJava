import java.io.OutputStream;
import java.io.IOException;


public class SecureOutputStream extends OutputStream {

  private Cipher cipher;
  private OutputStream out;
  HashFunction hf;

  public SecureOutputStream(Cipher c, OutputStream os){
    this.cipher = c;
    this.out = os;
    this.hf = new HashFunction();
  }


  public void write(int b)
           throws IOException {
    out.write(b);
  }


  public void write(byte[] b) 
         	throws IOException{
    hf.update(b);
    byte[] hashResult = hf.digest();

    byte[] plaintext = new byte[b.length+hashResult.length];
    System.arraycopy(b, 0, plaintext, 0, b.length);
    System.arraycopy(hashResult, 0, plaintext, b.length, hashResult.length);

    byte[] ciphertext = cipher.encryptCFB(plaintext);
    byte[] IV = cipher.getIV();

    byte[] message = new byte[ciphertext.length+IV.length+3];
    System.arraycopy(ciphertext, 0, message, 0, ciphertext.length);
    System.arraycopy(IV, 0, message, ciphertext.length, IV.length);
    message[message.length-1] = '\n';
    message[message.length-2] = '\n';
    message[message.length-3] = '\n';
  
    out.write(message);
  }


  public void close()
           throws IOException {
    out.close();
  }
}
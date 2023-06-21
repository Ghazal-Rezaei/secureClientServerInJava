import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;


public class ChatClient {
  public ChatClient(String username,
		    String serverHost, int serverPort,
		    byte[] clientPrivateKey, byte[] serverPublicKey)
                                                         throws IOException {

    SecureSocket sock = new SecureSocket(serverHost, serverPort,
            clientPrivateKey, serverPublicKey);
    
    System.out.println("Please enter your key:");
    Scanner sc = new Scanner(System.in);
    byte[] key = sc.nextLine().getBytes();

    SecureOutputStream out = sock.getOutputStream();
    SecureInputStream in = sock.getInputStream();
    sendAuth(username, in, out, key);

    new ReceiverThread(in);

    ByteArrayOutputStream temp = new ByteArrayOutputStream();
    for(;;){
      int c = System.in.read();
      if(c == -1)    break;
      temp.write(c);
      if(c == '\n') {  
        out.write(temp.toByteArray());
        temp.reset();
        out.flush();
      }
    }
    out.close();
  }

  public static void main(String[] argv){
    String username = argv[0];
    String hostname = (argv.length<=1) ? "localhost" : argv[1];
    try{
      new ChatClient(username, hostname, ChatServer.portNum, null, null);
    }catch(IOException x){
      x.printStackTrace();
    }
  }

  private void sendAuth(String username, SecureInputStream in, SecureOutputStream out, byte[] key) throws IOException {
    // create an AuthInfo object to authenticate the local user, 
    // and send the AuthInfo to the server

    AuthenticationInfo auth = new AuthenticationInfo(username);
    ObjectOutputStream oos = new ObjectOutputStream((OutputStream)out);
    oos.writeObject(auth);
    oos.flush();

    byte[] challenge = null;
    try{
      ByteArrayOutputStream baos;  
      baos = new ByteArrayOutputStream();
      for(;;){
	int c = in.read();
	if(c == -1){
	  break;
	}
	if(c == '\n'){
          int c1 = in.read();
          if(c1 == '\n'){
            int c2 = in.read();
            if(c2 == '\n')
	      challenge = in.integrityCheck(baos);
            else{
	      baos.write(c);
	      baos.write(c1);
	      baos.write(c2);
            }
        }
        else{
	  baos.write(c);
	  baos.write(c1);
	} 
	break;
	}
	baos.write(c);
      }
    }catch(IOException x){}
    
    try{
      BlockCipher blockCipher = new BlockCipher(key);
      Cipher cipher = new Cipher(blockCipher);
      out.write(cipher.decryptECB(challenge));
      out.flush();
    }catch(IOException x){}
  }

  class ReceiverThread extends Thread {
    // gather incoming messages, and display them

    private SecureInputStream in;

    ReceiverThread(SecureInputStream inStream) {
      in = inStream;
      start();
    }

    public void run() {
      try{
	ByteArrayOutputStream baos;  // queues up stuff until carriage-return
	baos = new ByteArrayOutputStream();
	for(;;){
	  int c = in.read();
	  if(c == -1){
	    break;
	  }
	  if(c == '\n'){
            int c1 = in.read();
            if(c1 == '\n'){
              int c2 = in.read();
              if(c2 == '\n')
	        spew(in.integrityCheck(baos));
              else{
	  	baos.write(c);
	  	baos.write(c1);
	  	baos.write(c2);
              }
            }
            else{
	      baos.write(c);
	      baos.write(c1);
	    }
	    continue;
	  }
	  baos.write(c);
	}
      }catch(IOException x){}
    }

    private void spew(byte[] message) throws IOException {
      System.out.write(message);
    }
  }
}

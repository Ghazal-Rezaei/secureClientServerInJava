import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.io.IOException;


public class ChatServer {
  public static final int portNum = Config.getAsInt("ServerPortNum");

  private Set activeSenders = Collections.synchronizedSet(new HashSet());

  public ChatServer(byte[] myPrivateKey) {
    // This constructor never returns.
    try{
      SecureServerSocket ss;
      System.out.println("I am listening on "+Integer.toString(portNum));
      ss = new SecureServerSocket(portNum, myPrivateKey);
      for(;;){
	// wait for a new client to connect, then hook it up properly
	SecureSocket sock = ss.accept();
	SecureInputStream  in  = sock.getInputStream();
	SecureOutputStream out = sock.getOutputStream();
	String username = getAuth(in,out);

	if(username != null) {
	  System.err.println("Got connection from " + username);
	  SenderThread st = new SenderThread(out);
	  new ReceiverThread(in, st, username);
	}
        else sock.close();
      }
    }catch(IOException x){
      System.err.println("Dying: IOException");
      x.printStackTrace();
    }
  }

  public static void main(String[] argv){
    new ChatServer(null);
  }

  private String getAuth(SecureInputStream in, SecureOutputStream out) throws IOException {
    try{
      ObjectInputStream ois = new ObjectInputStream((InputStream)in);
      Object o = ois.readObject();
      AuthenticationInfo auth = (AuthenticationInfo)o;
      return auth.getUserName(in,out);   // will return null if authentication fails
    }catch(ClassNotFoundException x){
      x.printStackTrace();
      return null;
    }
  }

  class SenderThread extends Thread {
    // forwards messages to a client
    // messages are queued
    // we take them from the queue and send them along

    private SecureOutputStream out;
    private Queue        queue;

    SenderThread(SecureOutputStream outStream) {
      out = outStream;
      queue = new Queue();
      activeSenders.add(this);
      start();
    }

    public void queueForSending(byte[] message){
      // queue a message, to be sent as soon as possible

      queue.put(message);
    }

    public void run() {
      // suck messages out of the queue and send them out
      try{
	for(;;){
	  Object o = queue.get();
	  byte[] barr = (byte[])o;
	  out.write(barr);
	  out.flush();
	}
      }catch(IOException x){
	// unexpected exception -- stop relaying messages
        System.out.println("unexpected exception stop relaying messages");
	x.printStackTrace();
	try{
	  out.close();
	}catch(IOException x2){
	x2.printStackTrace();

       }
      }
      activeSenders.remove(this);
    }
  }

  class ReceiverThread extends Thread {
    // receives messages from a client, and forwards them to everybody else

    private SecureInputStream  in;
    private SenderThread me;
    private byte[]       userNameBytes;

    ReceiverThread(SecureInputStream inStream, SenderThread mySenderThread,
		   String name) {
        System.out.println("amir");
      in = inStream;
      me = mySenderThread;
      String augmentedName = "[" + name + "] ";
      userNameBytes = augmentedName.getBytes();
      start();
    }

    public void run() {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      for(;;){
	// read in a message, terminated by carriage-return
	// buffer the message in baos, until we see EOF or carriage-return
	// then send it out to all the other clients
	try{
	  int c;
	  do{
	    c = in.read();
	    if(c == -1){
	      // got EOF -- send what we have, then quit
	      return;
	    }
	    if(c == '\n') {
              int c1 = in.read();
              if(c1 == '\n'){
                int c2 = in.read();
                if(c2 == '\n')
	          break;
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
	  }while(true);
	  sendToOthers(in.integrityCheck(baos));
	}catch(IOException x){
	  // send what we have, then quit
	  sendToOthers(in.integrityCheck(baos));
	  return;
	}
      }
    }

    private final SenderThread[] stArr = new SenderThread[1];

    private void sendToOthers(byte[] rawMessage) {
      // extract the contents of baos, and queue them for sending to all
      // other clients; 
      byte[] message = new byte[rawMessage.length+userNameBytes.length];
      System.arraycopy(userNameBytes, 0, message, 0, userNameBytes.length);
      System.arraycopy(rawMessage, 0, message, userNameBytes.length, rawMessage.length);

      SenderThread[] guys = (SenderThread[])(activeSenders.toArray(stArr));
      for(int i=0; i<guys.length; ++i){
	SenderThread st = guys[i];
	if(st != me)	st.queueForSending(message);
      }
    }
  }
}

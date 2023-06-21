// This file implements a secure (encrypted) version of the Socket class.
// (Actually, it is insecure as written, and students will fix the insecurities
// as part of their homework.)
//
// This class is meant to work in tandem with the SecureServerSocket class.
// The idea is that if you have a program that uses java.net.Socket and
// java.net.ServerSocket, you can make that program secure by replacing 
// java.net.Socket by this class, and java.net.ServerSocket by 
// SecureServerSocket.
//
// Like the ordinary Socket interface, this one differentiates between the
// client and server sides of a connection.  A server waits for connections
// on a SecureServerSocket, and a client uses this class to connect to a 
// server.
// 
// A client makes a connection like this:
//        String          serverHostname = ...
//        int             serverPort = ...
//        byte[]          myPrivateKey = ...
//        byte[]          serverPublicKey = ...
//        SecureSocket sock;
//        sock = new SecureSocket(serverHostname, serverPort,
//                                   myPrivateKey, serverPublicKey);
// 
// The keys are in a key-exchange protocol (which students will write), to
// establish a shared secret key that both the client and server know.
//
// Having created a SecureSocket, a program can get an associated
// InputStream (for receiving data that arrives on the socket) and an
// associated OutputStream (for sending data on the socket):
//
//         InputStream inStream = sock.getInputStream();
//         OutputStream outStream = sock.getOutputStream();


import java.io.InputStream;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.io.File;  // Import the File class
import java.io.FileNotFoundException;  // Import this class to handle errors
import java.util.Scanner; // Import the Scanner class to read text files


public class SecureSocket {
  private Socket       sock;
  private SecureInputStream  in;
  private SecureOutputStream out;

  public SecureSocket(String hostname, int port,
                      byte[] clientPrivateKey, byte[] serverPublicKey)
                         throws IOException, UnknownHostException {
    // this constructor is called by a client who wants to make a secure
    // socket connection to a server

    sock = new Socket(hostname, port);

    byte[] symmetricKey = keyExchange(clientPrivateKey, serverPublicKey, true);
    if(symmetricKey == null) sock.close();

    setupStreams(sock, symmetricKey, true);
  }

  public SecureSocket(Socket s, byte[] myPrivateKey) throws IOException {
    // don't call this yourself
    // this is meant to be called by SecureServerSocket

    sock = s;

    byte[] symmetricKey = keyExchange(myPrivateKey, null, false);
    if(symmetricKey == null) sock.close();

    setupStreams(sock, symmetricKey, false);
  }


  public static byte[] convertIntToByteArray(int value){
    return  ByteBuffer.allocate(4).putInt(value).array();
  }

  public static int convertByteArrayToInt(byte[] bytes) {
    return ByteBuffer.wrap(bytes).getInt();
  }

  public static byte[] concatByteArrays(byte[] a, byte[] b){
    try{
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write(a);
    outputStream.write(b);
    return outputStream.toByteArray();
    }catch(IOException x){}
    return null;
  }


  private byte[] keyExchange(byte[] myPrivateKey, 
			     byte[] hisPublicKey,  // null if I am server
			     boolean iAmClient ) throws IOException {

    InputStream instream = sock.getInputStream();
    OutputStream outstream = sock.getOutputStream();

    HashFunction hash = new HashFunction();

    int p1 = 0, p2 = 0, phi = 0, n = 0, e = 0, d = 0;

    if(iAmClient){
	try {
      		File myObj = new File("serverPublic.txt");
     		Scanner myReader = new Scanner(myObj);
        	n = Integer.parseInt(myReader.nextLine());
        	e = Integer.parseInt(myReader.nextLine());
	} catch (FileNotFoundException e1) {
      		System.out.println("An error occurred.");
    		e1.printStackTrace();
	}

	RSA rsa_server = new RSA(n,e);
	RSA rsa_client = new RSA();
	int[] clientPublicKey = rsa_client.getPublicKey();
	outstream.write(convertIntToByteArray(rsa_server.encrypt(clientPublicKey[0])));
	outstream.flush();
	outstream.write(convertIntToByteArray(rsa_server.encrypt(clientPublicKey[1])));
	outstream.flush();
	
	int nClient = Util.getRandomInt((int)Math.sqrt(Math.sqrt(Integer.MAX_VALUE))+1);
	outstream.write(convertIntToByteArray(rsa_server.encrypt(nClient)));
	outstream.flush();

  	byte[] inbytes = new byte[4];
   	int num = instream.read(inbytes, 0, inbytes.length);
	if(num != inbytes.length)    throw new RuntimeException();
	
	if(rsa_client.decryptOrSign(convertByteArrayToInt(inbytes)) == nClient){

   		num = instream.read(inbytes, 0, inbytes.length);
		if(num != inbytes.length)    throw new RuntimeException();
		int nServer = rsa_client.decryptOrSign(convertByteArrayToInt(inbytes));

		hash.update(concatByteArrays(convertIntToByteArray(nClient),convertIntToByteArray(nServer)));
		byte[] kSession = hash.digest();

		try{
			BlockCipher blockCipher = new BlockCipher(kSession);
      			Cipher cipher = new Cipher(blockCipher);
      			outstream.write(cipher.encryptECB(convertIntToByteArray(nServer)));
      			outstream.flush();
    		}catch(IOException x){}
		System.out.println("sent kSes");

		return kSession;
	}
    }
    else {
	try {
      		File myObj = new File("serverPrivate.txt");
     		Scanner myReader = new Scanner(myObj);
        	p1 = Integer.parseInt(myReader.nextLine());
        	p2 = Integer.parseInt(myReader.nextLine());
        	phi = Integer.parseInt(myReader.nextLine());
        	n = Integer.parseInt(myReader.nextLine());
        	e = Integer.parseInt(myReader.nextLine());
        	d = Integer.parseInt(myReader.nextLine());
	} catch (FileNotFoundException e2) {
      		System.out.println("An error occurred.");
    		e2.printStackTrace();
	}
	RSA rsa_server = new RSA(p1,p2,phi,n,e,d);

	byte[] inbytes = new byte[4];
   	int num = instream.read(inbytes, 0, inbytes.length);
	if(num != inbytes.length)    throw new RuntimeException();
	int n_client = rsa_server.decryptOrSign(convertByteArrayToInt(inbytes));

   	num = instream.read(inbytes, 0, inbytes.length);
	if(num != inbytes.length)    throw new RuntimeException();
	int e_client = rsa_server.decryptOrSign(convertByteArrayToInt(inbytes));

	RSA rsa_client = new RSA(n_client,e_client);

   	num = instream.read(inbytes, 0, inbytes.length);
	if(num != inbytes.length)    throw new RuntimeException();
	int nClient = rsa_server.decryptOrSign(convertByteArrayToInt(inbytes));
	outstream.write(convertIntToByteArray(rsa_client.encrypt(nClient)));
	outstream.flush();

	int nServer = Util.getRandomInt((int)Math.sqrt(Math.sqrt(Integer.MAX_VALUE))+1);
	outstream.write(convertIntToByteArray(rsa_client.encrypt(nServer)));
	outstream.flush();
	
	hash.update(concatByteArrays(convertIntToByteArray(nClient),convertIntToByteArray(nServer)));
	byte[] kSession = hash.digest();
	
	byte[] temp = new byte[8];
	try{
		BlockCipher blockCipher = new BlockCipher(kSession);
      		Cipher cipher = new Cipher(blockCipher);
      		num = instream.read(temp, 0, temp.length);
		if(num != temp.length)    throw new RuntimeException();
		inbytes = cipher.decryptECB(temp);
    	}catch(IOException x){x.printStackTrace();}	
	
	if(convertByteArrayToInt(inbytes) == nServer) return kSession;
    }
    System.out.println("there was a problem!");
    return null;
  }

  private void setupStreams(Socket ssock, 
			    byte[] symmetricKey, boolean iAmClient ) 
                                   throws IOException {
    BlockCipher blockCipher = new BlockCipher(symmetricKey);    
    Cipher cipher = new Cipher(blockCipher);


    in = new SecureInputStream(cipher,sock.getInputStream());
    out = new SecureOutputStream(cipher,sock.getOutputStream());
  }

  public SecureInputStream getInputStream() throws IOException {
    return in;
  }

  public SecureOutputStream getOutputStream() throws IOException {
    return out;
  }

  public void close() throws IOException {
    in.close();
    out.close();
    sock.close();
  }
}

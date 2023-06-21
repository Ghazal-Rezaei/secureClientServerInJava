import java.io.Serializable;
import java.io.IOException;
import java.io.File;  // Import the File class
import java.io.FileNotFoundException;  // Import this class to handle errors
import java.util.Scanner; // Import the Scanner class to read text files
import java.util.Arrays;
import java.io.ByteArrayOutputStream;


public class AuthenticationInfo implements Serializable {
  // The fields of this object are set by the client, and used by the 
  // server to validate the client's identity.  The client constructs this
  // object (by calling the constructor).  The client software (in another
  // source code file) then sends the object across to the server.  Finally,
  // the server verifies the object by calling isValid().

  private String username;

  public AuthenticationInfo(String name) {
    // This is called by the client to initialize the object.

    username = name;
  }

  public boolean isValid(SecureInputStream in, SecureOutputStream out) {
    // This is called by the server to make sure the user is who he/she 
    // claims to be.
    boolean clientExists = false, authorized = false;

    try {
      File myObj = new File("clientKeys.txt");
      Scanner myReader = new Scanner(myObj);
      while (myReader.hasNextLine()) {
        String[] client = myReader.nextLine().split("\\s+");
       
        if(client[0].equals(username)) {
	  clientExists = true;

          byte[] nonce = Util.getRandomByteArray(8);
          
          try {
            BlockCipher blockCipher = new BlockCipher(client[1].getBytes());
            Cipher cipher = new Cipher(blockCipher);
            byte[] challenge = cipher.encryptECB(nonce); 

            out.write(challenge);
            out.flush();
          }catch(IOException x){}

          byte[] response = null;
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
	            response = in.integrityCheck(baos);
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
          
          if(Arrays.equals(response,nonce))
	    authorized = true;
	}
    }
      myReader.close();
    } catch (FileNotFoundException e) {
      System.out.println("An error occurred.");
      e.printStackTrace();
    }

    return (clientExists && authorized);
  }

  public String getUserName(SecureInputStream in, SecureOutputStream out) {
    return isValid(in,out) ? username : null;
  }
}

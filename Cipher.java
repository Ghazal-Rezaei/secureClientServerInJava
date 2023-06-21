import java.util.Arrays;


public class Cipher {

    private BlockCipher blockCipher;
    private byte[] IV;

    public Cipher(BlockCipher bc){
      this.blockCipher = bc;

      Util generateIV = new Util();
      this.IV = generateIV.getRandomByteArray(8);
    }

    public Cipher(BlockCipher bc, byte[] IV){
      this.blockCipher = bc;
      this.IV = IV;
    }


   private int findPadLength(int len) {
     return (len%8 == 0) ? len : (len/8+1)*8;
   }


    public byte[] encryptECB(byte[] plainText) {
      int paddingLength = findPadLength(plainText.length);
      byte[] paddedPlainText = Arrays.copyOf(plainText, paddingLength);
      byte[] cipherText = new byte[paddingLength];
  
      for(int i=0; i<paddingLength/8; i++) {
        blockCipher.encrypt(paddedPlainText, i*8, cipherText, i*8);  
      }

      return cipherText;
    }


    public byte[] decryptECB(byte[] cipherText) {
      byte[] plainText = new byte[cipherText.length];
  
      for(int i=0; i<cipherText.length/8; i++) {
        blockCipher.decrypt(cipherText, i*8, plainText, i*8);  
      }

      return plainText;
    }


    public byte[] encryptCFB(byte[] plainText) {
      renewIV();  

      int paddingLength = findPadLength(plainText.length);
      byte[] paddedPlainText = Arrays.copyOf(plainText, paddingLength);
      byte[] cipherText = new byte[paddingLength];

      blockCipher.encrypt(this.IV,0,cipherText,0);
      for(int j=0; j<8; j++){
        cipherText[j] ^= paddedPlainText[j];      
      }
      for(int i=1; i<paddingLength/8; i++) {
        blockCipher.encrypt(cipherText, (i-1)*8, cipherText, i*8);  
        for(int j=i*8; j<(i+1)*8; j++){
          cipherText[j] ^= paddedPlainText[j]; 
        }
      }
    
      return cipherText;
    }


    public byte[] decryptCFB(byte[] cipherText, byte[] IV) {
      byte[] plainText = new byte[cipherText.length];

      blockCipher.encrypt(IV,0,plainText,0);
      for(int j=0; j<8; j++){
        plainText[j] ^= cipherText[j];      
      }
      for(int i=1; i<cipherText.length/8; i++) {
        blockCipher.encrypt(cipherText, (i-1)*8, plainText, i*8);  
        for(int j=i*8; j<(i+1)*8; j++){
          plainText[j] ^= cipherText[j]; 
        }
      }

      return plainText;
    }


    public byte[] getIV(){
      return this.IV;
    }
 
    
    public void renewIV(){
      Util generateIV = new Util();
      this.IV = generateIV.getRandomByteArray(8);
    }
}


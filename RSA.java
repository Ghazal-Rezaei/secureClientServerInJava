import java.lang.*;


public class RSA {
	private int prime1;
	private int prime2;
	private int phi;
	private int n;
	private int e;
	private int d;


	public RSA(){
		prime1 = findPrime();
		prime2 = findPrime();

		n = prime1*prime2;
		phi = (prime1-1)*(prime2-1);

		while(true){
			int t1 = Util.getRandomInt(phi-1)+1;
			int[] t2 = extendedEuclideanAlg(phi,t1);
			if(t2[0] == 1 && t2[2] >= 0){
				e = t1;
				d = t2[2];
				break;
			}
		}
/*		System.out.println(prime1);
		System.out.println(prime2);
		System.out.println(phi);
		System.out.println(n);
		System.out.println(e);
		System.out.println(d);	*/
	}


	public RSA(int p1, int p2, int phi, int n, int e, int d) {
		this.prime1 = p1;
		this.prime2 = p2;
		this.phi = phi;
		this.n = n;
		this.e = e;
		this.d = d;
	}	


	public RSA(int n, int e) {
		this.prime1 = 0;
		this.prime2 = 0;
		this.phi = 0;
		this.n = n;
		this.e = e;
		this.d = 0;
	}


	public int modularExponent(int x, int y, int p){
	// Here we use square and multiply algorithm for the purpose of fast exponentiation

		int ret = 1;

		x = x%p;
		// In case x is divisible by p
		if (x == 0) return 0;
		
		while (y > 0){
		// If y is odd, multiply x with result 		
			if((y & 1)==1)
				ret = (ret*x)%p;

			y = y>>1; 
		// Compute the square power of x mod p
			x = (int)Math.pow(x,2)%p; 
		}
		
		return ret;
	}


	public int[] largestOddFactor(int p){
	// For Miller-Rabin primality test, we need to find a tuple (u, r) such that p-1 = 2^u*r

		int u = 0;

		while(p%2==0){
			p = p/2;
			u++;
		}

		int[] ret = {u, p};
		return ret;
	}
	

	public boolean millerRabin(int p, int s){
	// Prime candidate p and security parameter s
	// returns true if p is recognized to be prime by the test

		if(p == 2 || p == 3) return true;

		if(p == 1 || p == 0) return false;
	
		int[] ur = largestOddFactor(p-1);
	
		for(int i=0 ; i < s; i++){
			// choosing an integer a in [2,p-2]
			int a = Util.getRandomInt(p-3)+2;
			int z = modularExponent(a, ur[1], p);
			if(z != 1 && z != p-1){
				for(int j=1 ; j < ur[0]; j++){
					z = modularExponent(z, 2, p);
					if(z == 1) return false;
				}
				if(z != p-1) return false;
			}
		}
		return true;
	}	


	public int findPrime(){
		int candidate;

		do {
			candidate = Util.getRandomInt((int)Math.sqrt(Math.sqrt(Integer.MAX_VALUE))+1);
		}while(!millerRabin(candidate,10));

		return candidate;
	}


	public int[] extendedEuclideanAlg(int m, int x){
	// returns a triple (d,s,t) such that d = gcd(m,x) and
	// d = m*s+x*t
	// When d=1, this method renders the modular inverse of x, with respect to the modulus m, as t (ret[2])

		int[] ret = new int[3];
		
		if (x == 0){
			ret[0] = m;
			ret[1] = 1;
			ret[2] = 0;
			return ret;
		}
		
		int[] temp = extendedEuclideanAlg(x, m%x);
		ret[0] = temp[0];
		ret[1] = temp[2];
		ret[2] = temp[1]-((int)m/x)*temp[2];

		return ret;
	}


	public int[] getPublicKey(){
		int[] ret = {n,e};
		return ret;
	}

	
	public int encrypt(int x){
		return modularExponent(x,e,n);
	}

	
	public int decryptOrSign(int x){
		return modularExponent(x,d,n);
	}

}
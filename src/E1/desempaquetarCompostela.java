package E1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class desempaquetarCompostela {
	public static void main(String[] args) throws Exception {
		// Elementos:
		// Clave Privada oficina - 0
		// Clave Publica peregrino - 1
		// Clave aleatoria secreta - 2
		// Firma - 3
		// Compostela sin cifrar - 4
		// Compostela cifrada - 5
		if (args.length != 6) {
			mensajeAyuda();
			System.exit(1);
		}

		Security.addProvider(new BouncyCastleProvider());

		// Desencriptar la clave secreta aleatoria args[2] con clave privada de la oficina args[0]
		byte[] buffer = new byte[5000];
		byte[] bufferCifrado;

		FileInputStream in = new FileInputStream(args[0]);
		in.read(buffer, 0, 5000);
		in.close();

		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAprofesor = KeyFactory.getInstance("RSA", "BC");
		PrivateKey clavePrivadaOficina = keyFactoryRSAprofesor.generatePrivate(clavePrivadaSpec);
	
		buffer = new byte[64];
		in = new FileInputStream(args[2]);
		in.read(buffer, 0, 64);
		in.close();
		
		Cipher cifrador = Cipher.getInstance("RSA","BC");
		cifrador.init(Cipher.DECRYPT_MODE, clavePrivadaOficina);
		bufferCifrado = cifrador.doFinal(buffer);
		
		DESKeySpec DESspec = new DESKeySpec(bufferCifrado);
		SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
		SecretKey claveAleatoriaDesencriptada = secretKeyFactoryDES.generateSecret(DESspec);

		/*****************************************************************/
		//Desencripta los datos del peregrino args[6] con la clave secreta aleatoria desencriptada

		//Coger la firma
		buffer = new byte[5000];
		in = new FileInputStream(args[1]);
		in.read(buffer, 0, 5000);
		in.close();
		
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		PublicKey clavePublicaPeregrino = keyFactoryRSA.generatePublic(clavePublicaSpec);
		
		Signature firma = Signature.getInstance("SHA1withRSA","BC");
		firma.initVerify(clavePublicaPeregrino);
		
		Cipher cifrador2 = Cipher.getInstance("DES/ECB/PKCS5Padding");
		cifrador2.init(Cipher.DECRYPT_MODE, claveAleatoriaDesencriptada);
		buffer = new byte[1000];
		
		FileInputStream in2 = new FileInputStream(args[5]);
		FileOutputStream out = new FileOutputStream("Compostela.descifrado");
		byte[] bufferPlano;
		int bytesLeidos = in2.read(buffer, 0, 1000);
		while (bytesLeidos != -1) {
			bufferPlano = cifrador2.update(buffer, 0, bytesLeidos);
			out.write(bufferPlano);
			bytesLeidos = in2.read(buffer, 0, 1000);   
			firma.update(bufferPlano);
		}
		bufferPlano = cifrador2.doFinal();

		firma.update(bufferPlano);
		out.write(bufferPlano);
		
		/*****************************************************************************/
		//Genera Compostela.descifrado
		in2.close();
		out.close();
		FileInputStream l1 = new FileInputStream("Compostela.descifrado");
		FileInputStream l2 = new FileInputStream(args[4]);

		int content;
		String todo = "";
		while((content = l1.read()) != -1){
			todo += (char) content;//todo contiene el contenido de Compostela.descifrado
		}
		int content2;
		String todo2 = "";
		while((content2 = l2.read()) != -1){
			todo2 += (char) content2;//todo2 contiene el contenido de Compostela.sinCifrar
		}
		l1.close();
		l2.close();
		if(todo.equals(todo2)){
			System.out.println("Compostela correcta, datos:");
			System.out.println(todo);
			System.out.println("Se procede a comprobar la firma...");
			System.out.println();

		}else{
			System.out.println("Compostela incorrecta, no corresponde con la creada por el peregrino.");
		}
		
		/*****************************************************************************/
		//Desencriptar firma args[3]
		File f = new File (args[2]);
		byte[] bufferFirma = new byte[(int)f.length()];
		
		in = new FileInputStream(args[3]);
		in.read(bufferFirma, 0, (int)f.length());
		in.close();

		if (firma.verify(bufferFirma)) {
			System.out.println ("Firma confirmada, todo correcto");
		}
		else {
			System.out.println ("Firma erronea");
		}

	}

	public static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void mensajeAyuda() {
		System.out.println("Error en los elementos introducidos por comando");
		System.out
				.println("\tSintaxis:  Clave Privada oficina / "
						+ "Clave Publica peregrino / "
						+ "Clave aleatoria secreta / "
						+ "Firma / "
						+ "Compostela sin cifrar / "
						+ "Compostela cifrada");
		System.out.println();
	}

}

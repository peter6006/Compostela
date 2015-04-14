package E1;

import javax.crypto.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class generarCompostela {

	public static void main(String[] args) throws Exception {
		// 2 argumentos:
		// clave publica de la oficina
		// clave privada del peregrino
		if (args.length != 2) {
			mensajeAyuda();
			System.exit(1);
		}
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Map<String, String> datos = new HashMap<String, String>();
		Scanner ini = new Scanner(System.in);
		System.out.print("Nombre : ");
		String nombre = ini.nextLine();
		datos.put("nombre", nombre);

		System.out.print("DNI : ");
		String dni = ini.nextLine();
		datos.put("dni", dni);
		
		System.out.print("Domicilio : ");
		String domicilio = ini.nextLine();
		datos.put("domicilio", domicilio);
		
		System.out.print("Fecha  : ");
		String fecha = ini.nextLine();
		datos.put("fecha", fecha);

		System.out.print("Lugar  : ");
		String lugar = ini.nextLine();
		datos.put("lugar", lugar);
		
		System.out.print("Motivaciones  : ");
		String motivaciones = ini.nextLine();
		datos.put("motivaciones", motivaciones);
		ini.close();

		String json = Utils.map2json(datos);
		byte[] c = json.getBytes();

		FileOutputStream compostela = new FileOutputStream("compostela.sinCifrar");
		compostela.write(c);
		compostela.close();
		 
		/*****************************************************************/
		//Cifrar datos de la compostela con DES con la clave secreta aleatoria
		Security.addProvider(new BouncyCastleProvider());
		
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56);
		SecretKey clave = generadorDES.generateKey();

		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");

		cifrador.init(Cipher.ENCRYPT_MODE, clave);

		byte[] buffer = new byte[1000];
		byte[] bufferCifrado;

		FileInputStream in = new FileInputStream("compostela.sinCifrar");
		FileOutputStream out = new FileOutputStream("compostela.cifrado");

		int bytesLeidos = in.read(buffer, 0, 1000);
		while (bytesLeidos != -1) {
			bufferCifrado = cifrador.update(buffer, 0, bytesLeidos);
			out.write(bufferCifrado);
			bytesLeidos = in.read(buffer, 0, 1000);
		}
		bufferCifrado = cifrador.doFinal(); 
		out.write(bufferCifrado);

		in.close();
		out.close();

		/*****************************************************************/
		// Cifrar clave con RSA y la clave publica de la oficina
		
		buffer = new byte[5000];
		in = new FileInputStream(args[0]);
		in.read(buffer, 0, 5000);
		in.close();
		
		X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAprofesor = KeyFactory.getInstance("RSA", "BC");
		PublicKey clavePublicaOficina = keyFactoryRSAprofesor.generatePublic(clavePublicaSpec);
				
		cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, clavePublicaOficina);
		bufferCifrado = cifrador.doFinal(clave.getEncoded());

		out = new FileOutputStream("Clave.cifrada");
		out.write(bufferCifrado);
		out.close();

		/*****************************************************************************/
		// Crear firma
		buffer = new byte[5000];
		in = new FileInputStream(args[1]);
		in.read(buffer, 0, 5000);
		in.close();
		
		PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(buffer);
		KeyFactory keyFactoryRSAalumno = KeyFactory.getInstance("RSA", "BC");
		PrivateKey clavePrivadaPeregrino = keyFactoryRSAalumno.generatePrivate(clavePrivadaSpec);
		
		Signature firma = Signature.getInstance("SHA1withRSA","BC");
		firma.initSign(clavePrivadaPeregrino);
		
		buffer = new byte[1000];
		in = new FileInputStream("compostela.sinCifrar");
		
		bytesLeidos = in.read(buffer, 0, 1000);
		while (bytesLeidos != -1) {
			firma.update(buffer, 0, bytesLeidos);
			bytesLeidos = in.read(buffer, 0, 1000);
		}
		byte[] firmaEncriptada = firma.sign();

		out = new FileOutputStream("firma");
		out.write(firmaEncriptada);
		
		in.close();
		out.close();
		System.out.println("Creacion correcta, buen viaje");

	}

	public static void mostrarBytes(byte[] buffer) {
		System.out.write(buffer, 0, buffer.length);
	}

	public static void mensajeAyuda() {
		System.out.println("Error en los elementos introducidos por comando");
		System.out.println("\tSintaxis:  Clave publica de la oficina / clave privada del peregrino");
		System.out.println();
	}

	public static byte[] leerLinea(java.io.InputStream in) throws IOException {
		byte[] buffer1 = new byte[1000];
		int i = 0;
		byte c;
		c = (byte) in.read();
		while ((c != '\n') && (i < 1000)) {
			buffer1[i] = c;
			c = (byte) in.read();
			i++;
		}

		byte[] buffer2 = new byte[i];
		for (int j = 0; j < i; j++) {
			buffer2[j] = buffer1[j];
		}
		return (buffer2);
	}

}

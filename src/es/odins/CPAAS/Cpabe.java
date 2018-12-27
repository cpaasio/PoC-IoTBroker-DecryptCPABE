package es.odins.CPAAS;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @author juan
 *
 */
public class Cpabe {

	public static final int TYPE1R_160Q_512 	= 1;
	public static final int TYPE1R_224Q_1024 	= 2;
	public static final int TYPE1R_256Q_1536 	= 3;

	public static final String pubFile = "pubFile";
	public static final String mskFile = "mskFile";
	public static final String privFile = "privFile";
	public static final String policy = "manufacturer:OdinS and model:RexLab and project:CPAAS";
	public static final String[] attrib = {"manufacturer:OdinS","model:RexLab","project:CPAAS"};
	public static final String textFile = "textFile.txt";
	public static final String encryptedFile = "encryptedFile.cpabe";
	public static final String decryptedFile = "decryptedFile.txt";
	
	
	public static void main(String[] args) {
		//Cpabe.getTick();
		
		try {
			/*
			 * Se crea un par de claves maestras publico/privada para la autoridad de claves
			 */
			Cpabe.setup(pubFile, mskFile, TYPE1R_160Q_512);
			/*
			 * La autoridad de claves genera una privada para un cliente especifico, 
			 * asignandole X atributos
			 */
			Cpabe.keygen(pubFile, mskFile,privFile, attrib);
			
			/**
			 * Alguien cifra un archivo con su clave publica y una politica de descifrado
			 */
			Cpabe.encrypt(pubFile, policy, textFile,encryptedFile);
			/**
			 * Un cliente intenta descifrar un archivo usando su clave publica y privada. Su clave privada cumple la politica de descifrado
			 */
			Cpabe.decrypt(pubFile, privFile, encryptedFile,decryptedFile);
			
			
		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		
		System.out.println("done");
	}
	
	static {
		//System.out.println("System.getProperty(\"java.library.path\") is: " + System.getProperty("java.library.path"));
		//System.setProperty("LD_LIBRARY_PATH",System.getProperty("LD_LIBRARY_PATH")+"./lib");
		System.loadLibrary("cpabe");
	}
	/**
	 * 
	 * @author juan
	 *
	 */
	//public static native float getTick();
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacenara la clave publica maestra
	 * @param mskFile Nombre del archivo, donde se almacenara la clave privada maestra
	 * @param parameters_type tipo de claves
	 * @return
	 */
	public static native void setup(String pubFile, String mskFile, int parameters_type) throws IOException;
	/**
	 * 
	 * @param pubFile Clave publica maestra
	 * @param mskFile Clave privada maestra
	 * @param attributes Atributos publicos de un cliente especifico
	 * @return Clave privada
	 */
	public static native byte[] keygen (String pubFile, String mskFile, String[] attributes) throws IOException;
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param mskFile Nombre del archivo, donde se almacena la clave privada maestra
	 * @param attributes Atributos publicos separados por espacio, de un cliente especifico
	 * @return Clave privada
	 * @throws IOException 
	 */
	public static byte[] keygen (String pubFile, String mskFile, String attributes) throws IOException{
		
		return keygen(pubFile,mskFile,attributes.split(" "));
	}
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param mskFile Nombre del archivo, donde se almacena la clave privada maestra
	 * @param privFile Nombre del archivo, donde se almacenara la clave privada
	 * @param attributes Atributos publicos, de un cliente especifico
	 * @throws IOException 
	 */
	public static void keygen (String pubFile, String mskFile,String privFile, String attributes) throws IOException{
		keygen(pubFile,mskFile,privFile,attributes.split(" "));
	}
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param mskFile Nombre del archivo, donde se almacena la clave privada maestra
	 * @param privFile Nombre del archivo, donde se almacenara la clave privada
	 * @param attributes Atributos publicos separados por espacio, de un cliente especifico
	 * @throws IOException 
	 */
	public static void keygen (String pubFile, String mskFile,String privFile, String[] attributes) throws IOException{
		FileOutputStream stream = null;
		try{
			stream = new FileOutputStream(privFile);
			
			stream.write(keygen(pubFile, mskFile, attributes));
		}finally {
			stream.close();
		}
	}
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param jpolicy Cadena con la politica de descifrado
	 * @param data	Mensaje a cifrar
	 * @return Mensaje cifrado
	 * @throws EncryptException
	 * @throws IOException
	 */
	public static native byte[] encryptMessage ( String pubFile, String jpolicy,byte[] data) throws EncryptException, IOException;
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param prvFile Nombre del archivo, donde se almacena la clave privada
	 * @param data Mensaje a descifrar
	 * @return Mensaje descifrado
	 * @throws DecryptException
	 * @throws IOException
	 */
	public static native byte[] decryptMessage (String pubFile, String prvFile, byte[] data) throws DecryptException,IOException; 
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param jpolicy Cadena con la politica de descifrado
	 * @param inFile Archivo a cifrar
	 * @param outFile Archivo cifrado
	 * @throws EncryptException
	 * @throws IOException
	 */
	public static void encrypt(String pubFile, String jpolicy,String inFile, String outFile) throws EncryptException, IOException{
		File ifd = new File(inFile);
		FileOutputStream stream = null;
		FileInputStream istream = null;
		try {
			stream = new FileOutputStream(outFile);
			istream = new FileInputStream(ifd);
			
			byte [] inData = new byte[(int) ifd.length()];
			istream.read(inData);
			
			
		    stream.write(encryptMessage(pubFile,jpolicy,inData));
		} finally {
		    if(stream!=null)
		    	stream.close();

		    if(istream!=null)
		    	istream.close();
		}
	};
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param jpolicy Cadena con la politica de descifrado
	 * @param inFile Archivo a cifrar. Se usa el mismo archivo para guardar el resultado
	 * @throws EncryptException
	 * @throws IOException
	 */
	public static void encrypt(String pubFile, String jpolicy,String inOutFile) throws EncryptException, IOException{
		encrypt(pubFile,jpolicy,inOutFile,inOutFile);
	}
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param prvFile Nombre del archivo, donde se almacena la clave privada
	 * @param inFile Archivo a descifrar
	 * @param outFile Archivo descifrado
	 * @throws DecryptException
	 * @throws IOException
	 */
	public static void decrypt(String pubFile, String prvFile,String inFile, String outFile) throws DecryptException, IOException{
		File ifd = new File(inFile);
		FileOutputStream stream = null;
		FileInputStream istream = null;
			try {
				stream = new FileOutputStream(outFile);
				istream = new FileInputStream(ifd);
				
				byte [] inData = new byte[(int) ifd.length()];
				istream.read(inData);
				
				
			    stream.write(decryptMessage(pubFile,prvFile,inData));
			} finally {
			    if(stream!=null)
			    	stream.close();
	
			    if(istream!=null)
			    	istream.close();
			}
	};
	/**
	 * 
	 * @param pubFile Nombre del archivo, donde se almacena la clave publica maestra
	 * @param prvFile Nombre del archivo, donde se almacena la clave privada
	 * @param inFile Archivo a descifrar. Se usa el mismo archivo para guardar el resultado
	 * @throws DecryptException
	 * @throws IOException
	 */
	public static void decrypt(String pubFile, String prvFile,String inFile) throws DecryptException, IOException{
		decrypt(pubFile,prvFile,inFile,inFile);
	}
	
}

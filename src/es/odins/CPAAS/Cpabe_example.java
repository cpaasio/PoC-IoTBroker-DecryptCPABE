package es.odins.CPAAS;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import es.odins.CPAAS.Cpabe;

/**
 * 
 * @author juan
 *
 */
public class Cpabe_example {

	public static final int TYPE1R_160Q_512 	= 1;
	public static final int TYPE1R_224Q_1024 	= 2;
	public static final int TYPE1R_256Q_1536 	= 3;

	public static final String masterPublic = "pubFile";
	public static final String masterPrivate = "mskFile";
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
			Cpabe.setup(masterPublic, masterPrivate, TYPE1R_160Q_512);
			/*
			 * La autoridad de claves genera una privada para un cliente especifico, 
			 * asignandole X atributos
			 */
			Cpabe.keygen(masterPublic, masterPrivate,privFile, attrib);
			
			/**
			 * Alguien cifra un archivo con su clave publica y una politica de descifrado
			 */
			Cpabe.encrypt(masterPublic, policy, textFile,encryptedFile);
			/**
			 * Un cliente intenta descifrar un archivo usando su clave publica y privada. Su clave privada cumple la politica de descifrado
			 */
			Cpabe.decrypt(masterPublic, privFile, encryptedFile,decryptedFile);
			
			
		}catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		
		
		System.out.println("done");
	}
	
}

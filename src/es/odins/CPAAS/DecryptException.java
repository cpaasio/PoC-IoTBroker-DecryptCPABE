package es.odins.CPAAS;

public class DecryptException extends Exception{
	private static final long serialVersionUID = -4848483797969031667L;
	
	public DecryptException(){}
	
	public DecryptException(String msg){
		super(msg);
	}
}

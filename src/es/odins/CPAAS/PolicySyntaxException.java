package es.odins.CPAAS;

public class PolicySyntaxException extends IllegalArgumentException{
	private static final long serialVersionUID = 728507858998663424L;
	
	public PolicySyntaxException(String msg){
		super(msg);
	}
	public PolicySyntaxException(){}
}

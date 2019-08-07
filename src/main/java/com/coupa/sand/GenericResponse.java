package com.coupa.sand;

public class GenericResponse<R> {

	private int statusCode;
	private R response;
	
	public GenericResponse(int statusCode, R response) {
		super();
		this.statusCode = statusCode;
		this.response = response;
	}
	
	public int getStatusCode() {
		return statusCode;
	}
	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}
	public R getResponse() {
		return response;
	}
	public void setResponse(R response) {
		this.response = response;
	}
}

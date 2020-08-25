package com.solitardj9.authService.serviceInterface.common;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;

public enum StatusCode {
	//
	Success(200, "Success", HttpStatus.OK),
	Invalid_Request(400, "InvalidRequestException", HttpStatus.BAD_REQUEST),
	Invalid_Body_Error(400, "InvalidBodyError", HttpStatus.BAD_REQUEST),
	Resource_Not_Found(404, "ResourceNotFoundException.", HttpStatus.NOT_FOUND),
	Resource_Already_Exist(409, "ResourceAlreadyExistsException.", HttpStatus.CONFLICT),
	INTERNAL_SERVER_ERROR(500, "InternalFailureException.", HttpStatus.INTERNAL_SERVER_ERROR),
	;
	
	private Integer code;
	private String message;
	private HttpStatus httpStatus;
	
	StatusCode(Integer code, String message, HttpStatus httpStatus) {
		this.code = code;
		this.message = message;
		this.httpStatus = httpStatus;
	}
	
	public Integer getCode() {
		return this.code;
	}
	
	public String getMessage() {
		return this.message;
	}
	
	public HttpStatus getHttpStatus() {
		return httpStatus;
	}

	public Map<String,String> getMapMessage() {
		//
		Map<String, String> messageMap = new HashMap<>();
		messageMap.put("message", this.getMessage());
		return messageMap;
	}
}
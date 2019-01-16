package com.bigbilii.entity;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Result implements Serializable {

    private int code;

    private String message;

    private Map<String,Object> data = new HashMap<String, Object>();

    private Result(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public static Result message(int code,String message){
        Result result = new Result(code, message);
        return result;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public void setData(Map<String, Object> data) {
        this.data = data;
    }
    public Result add(String key,Object value){
        this.data.put(key,value);
        return this;
    }
}

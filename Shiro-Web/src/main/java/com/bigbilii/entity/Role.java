package com.bigbilii.entity;

import java.io.Serializable;
import java.util.List;


public class Role implements Serializable {
    private int id; //角色编号
    private String name; //角色标识 程序中判断使用，如"admin"
    private String description; //角色描述，UI界面显示使用

    public Role() {
    }

    public Role(String name, String description) {
        this.name = name;
        this.description = description;
    }


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getname() {
        return name;
    }

    public void setname(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "name{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                '}';
    }
}

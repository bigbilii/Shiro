package com.bigbilii.entity;


public class Permission {
    private int id; //权限编号
    private String name; //权限标识 程序中判断使用，如"user:create"
    private String description; //权限描述。UI界面显示用

    public Permission() {
    }

    public Permission(String name, String description) {
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

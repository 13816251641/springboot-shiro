package com.lujieni.springbootshiro.entity;

import lombok.Data;

@Data
public class SysPermissionInit {
    private Integer id;
    private String url;
    private String permissionInit;
    private Integer sort;
}

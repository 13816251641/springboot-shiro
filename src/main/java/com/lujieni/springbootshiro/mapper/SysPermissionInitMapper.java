package com.lujieni.springbootshiro.mapper;

import com.lujieni.springbootshiro.entity.SysPermissionInit;
import com.lujieni.springbootshiro.entity.User;
import org.springframework.stereotype.Repository;

import java.util.List;

/*该标签如果没有也没有关系,加了service层就不会报注入警告*/
@Repository
public interface SysPermissionInitMapper {
    List<SysPermissionInit> getAll();
}

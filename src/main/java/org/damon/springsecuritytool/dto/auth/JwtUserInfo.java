package org.damon.springsecuritytool.dto.auth;

import lombok.Data;
import org.damon.springsecuritytool.dto.response.ResponseData;

import java.util.List;

/**
 * @author damon 20250521
 */
@Data
public class JwtUserInfo implements ResponseData {
    /*
     * userId
     */
    private String userId;
    /*
     * username
     */
    private String username;
    /*
     * city
     */
    private String city;
    /*
     * roleList
     */
    private List<Role> roleList;
    /*
     * dataList
     */
    private List<String> dataList;
}

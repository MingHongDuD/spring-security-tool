package org.damon.springsecuritytool.dto.response;

import lombok.Data;

/**
 * @author damon 20250521
 */
@Data
public class ResponseDTOImpl implements ResponseDTO {
    /*
     * isSuccess
     */
    private boolean isSuccess = false;
    /*
     * errorMsg
     */
    private String errorMsg;
    /*
     * sessionId
     */
    private String sessionId;
    /*
     * data
     */
    private ResponseData data;
}

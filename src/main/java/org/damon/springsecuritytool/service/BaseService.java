package org.damon.springsecuritytool.service;

import org.damon.springsecuritytool.dto.request.RequestDTO;
import org.damon.springsecuritytool.dto.response.ResponseDTO;

/**
 * @author damon 20250521
 */
public interface BaseService {
    ResponseDTO run(RequestDTO requestDTO);
}

package org.damon.springsecuritytool.controller;

import org.damon.springsecuritytool.dto.request.RequestDTO;
import org.damon.springsecuritytool.dto.response.ResponseDTO;
import org.damon.springsecuritytool.service.BaseService;
import org.springframework.context.ApplicationContext;

/**
 * @author damon
 */
public class BaseRestController {

    private final ApplicationContext context;

    public BaseRestController(ApplicationContext context) {
        this.context = context;
    }

    public ResponseDTO execute(RequestDTO requestDTO, Class<? extends BaseService> service) {
        return context.getBean(service).run(requestDTO);
    }
}

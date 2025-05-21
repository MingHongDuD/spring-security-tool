package org.damon.springsecuritytool.controller;

import org.damon.springsecuritytool.dto.response.ResponseDTO;
import org.damon.springsecuritytool.service.impl.UserRestServiceImpl;
import org.springframework.context.ApplicationContext;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author damon 20250521
 */
@RestController
@RequestMapping("/user")
public class RestUserController extends BaseRestController {

    public RestUserController(ApplicationContext context) {
        super(context);
    }

    @PostMapping
    public ResponseDTO user() {
        return execute(null, UserRestServiceImpl.class);
    }
}

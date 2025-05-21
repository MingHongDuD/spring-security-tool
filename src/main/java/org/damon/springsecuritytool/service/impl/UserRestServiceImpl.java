package org.damon.springsecuritytool.service.impl;

import org.damon.springsecuritytool.auth.JwtTokenProvider;
import org.damon.springsecuritytool.dto.request.RequestDTO;
import org.damon.springsecuritytool.dto.response.ResponseData;
import org.springframework.stereotype.Service;

/**
 * @author damon 20250521
 */
@Service
public class UserRestServiceImpl extends BaseServiceImpl {

    private final JwtTokenProvider jwtTokenProvider;

    public UserRestServiceImpl(JwtTokenProvider jwtTokenProvider) {
        super(jwtTokenProvider);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected ResponseData execute(RequestDTO requestDTO) {
        return jwtTokenProvider.getJwtUserInfo();
    }
}

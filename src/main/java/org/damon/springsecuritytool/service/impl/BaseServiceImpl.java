package org.damon.springsecuritytool.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.damon.springsecuritytool.auth.JwtTokenProvider;
import org.damon.springsecuritytool.dto.auth.Violation;
import org.damon.springsecuritytool.dto.request.RequestDTO;
import org.damon.springsecuritytool.dto.response.ResponseDTO;
import org.damon.springsecuritytool.dto.response.ResponseDTOImpl;
import org.damon.springsecuritytool.dto.response.ResponseData;
import org.damon.springsecuritytool.exception.ValidationException;
import org.damon.springsecuritytool.service.BaseService;

/**
 * @author damon 20250521
 */
@Slf4j
public abstract class BaseServiceImpl implements BaseService {

    private final JwtTokenProvider jwtTokenProvider;

    protected BaseServiceImpl(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public ResponseDTO run(RequestDTO requestDTO) {

        ResponseDTOImpl responseDtoImpl = new ResponseDTOImpl();
        try {
            log.info(this.getClass().getName());
            log.info("userid: {}, roles: {}", jwtTokenProvider.getJwtUserInfo().getUserId(), jwtTokenProvider.getJwtUserInfo().getRoleList());
            log.info("request: {}", requestDTO);
            responseDtoImpl.setData(execute(requestDTO));
            responseDtoImpl.setSuccess(true);
            responseDtoImpl.setSessionId(jwtTokenProvider.refreshToken());
        } catch (ValidationException e) {
            responseDtoImpl.setSuccess(false);
            if (!e.getViolations().isEmpty()) {
                Violation violation = e.getViolations().getFirst();
                responseDtoImpl.setErrorMsg(violation.getMessage());
                log.error(violation.getMessage());
            }
            return responseDtoImpl;
        } catch (Exception e) {
            responseDtoImpl.setSuccess(false);
            log.error(e.toString());
        }
        return responseDtoImpl;
    }

    protected abstract ResponseData execute(RequestDTO requestDTO);
}

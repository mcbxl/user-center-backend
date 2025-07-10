package com.yupi.usercenter.utils;

import com.yupi.usercenter.model.domain.User;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Session工具类
 *
 * @author yupi
 */
@Slf4j
public class SessionUtils {

    /**
     * 用户登录态键
     */
    private static final String USER_LOGIN_STATE = "userLoginState";

    /**
     * 获取当前登录用户
     *
     * @param request
     * @return
     */
    public static User getLoginUser(HttpServletRequest request) {
        if (request == null) {
            log.warn("HttpServletRequest is null");
            return null;
        }
        
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.warn("Session is null");
            return null;
        }
        
        User user = (User) session.getAttribute(USER_LOGIN_STATE);
        if (user == null) {
            log.warn("User not found in session");
            return null;
        }
        
        log.info("Current login user: {}", user.getUserAccount());
        return user;
    }

    /**
     * 设置登录用户到session
     *
     * @param request
     * @param user
     */
    public static void setLoginUser(HttpServletRequest request, User user) {
        if (request == null) {
            log.warn("HttpServletRequest is null, cannot set user to session");
            return;
        }
        
        if (user == null) {
            log.warn("User is null, cannot set to session");
            return;
        }
        
        HttpSession session = request.getSession(true);
        session.setAttribute(USER_LOGIN_STATE, user);
        log.info("User {} set to session successfully", user.getUserAccount());
    }

    /**
     * 清除登录用户
     *
     * @param request
     */
    public static void clearLoginUser(HttpServletRequest request) {
        if (request == null) {
            return;
        }
        
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(USER_LOGIN_STATE);
            log.info("User removed from session");
        }
    }

    /**
     * 检查用户是否已登录
     *
     * @param request
     * @return
     */
    public static boolean isLogin(HttpServletRequest request) {
        User user = getLoginUser(request);
        return user != null;
    }

    /**
     * 调试session信息
     *
     * @param request
     */
    public static void debugSession(HttpServletRequest request) {
        if (request == null) {
            log.info("HttpServletRequest is null");
            return;
        }
        
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.info("Session is null");
            return;
        }
        
        log.info("Session ID: {}", session.getId());
        log.info("Session creation time: {}", session.getCreationTime());
        log.info("Session last accessed time: {}", session.getLastAccessedTime());
        log.info("Session max inactive interval: {}", session.getMaxInactiveInterval());
        
        User user = (User) session.getAttribute(USER_LOGIN_STATE);
        if (user != null) {
            log.info("User in session: {}", user.getUserAccount());
        } else {
            log.info("No user found in session");
        }
    }
} 
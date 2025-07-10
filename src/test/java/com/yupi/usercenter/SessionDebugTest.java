package com.yupi.usercenter;

import com.yupi.usercenter.model.domain.User;
import com.yupi.usercenter.utils.SessionUtils;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Session调试测试
 *
 * @author yupi
 */
@SpringBootTest
public class SessionDebugTest {

    @Test
    void testSessionDebug() {
        // 创建MockHttpServletRequest
        MockHttpServletRequest request = new MockHttpServletRequest();
        
        // 调试空的session
        System.out.println("=== 调试空的session ===");
        SessionUtils.debugSession(request);
        
        // 创建一个测试用户
        User testUser = new User();
        testUser.setId(1L);
        testUser.setUserAccount("testuser");
        testUser.setUsername("测试用户");
        
        // 设置用户到session
        System.out.println("\n=== 设置用户到session ===");
        SessionUtils.setLoginUser(request, testUser);
        
        // 再次调试session
        System.out.println("\n=== 调试设置后的session ===");
        SessionUtils.debugSession(request);
        
        // 获取登录用户
        System.out.println("\n=== 获取登录用户 ===");
        User loginUser = SessionUtils.getLoginUser(request);
        if (loginUser != null) {
            System.out.println("获取到的用户: " + loginUser.getUserAccount());
        }
        
        // 检查是否登录
        System.out.println("\n=== 检查登录状态 ===");
        boolean isLogin = SessionUtils.isLogin(request);
        System.out.println("是否已登录: " + isLogin);
    }
} 
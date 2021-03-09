from django.urls import path
from users.views import ForgetPasswordView, ImageCodeView
from users.views import LoginView, LogoutView
from users.views import RegisterView, SmsCodeView
from users.views import  UserCenterView, WriteBlogView

urlpatterns = [
    # 参数1：路由
    # 参数2： 视图函数
    # 参数3：路由名，方便通过reverse获取路由
    path('register/', RegisterView.as_view(), name='register'),
    # 图片验证码路由
    path('imagecode/', ImageCodeView.as_view(), name='imagecode'),

    # 短信验证码路由
    path('smscode/', SmsCodeView.as_view(), name='smscode'),

    #登录路由
    path('login/', LoginView.as_view(), name='login'),

    #退出登录路由
    path('logout/', LogoutView.as_view(), name='logout'),

    # 忘记密码路由
    path('forgetpassword/', ForgetPasswordView.as_view(), name='forgetpassword'),

    # 个人中心
    path('center/', UserCenterView.as_view(), name='center'),

    # 写博客
    path('writeblog/', WriteBlogView.as_view(), name='writeblog' )
]

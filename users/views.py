from django.shortcuts import render

import re
from django.views import View
from users.models import User
from django.db import DatabaseError
from django.shortcuts import redirect
from django.urls import reverse
# Create your views here.

# 注册页面
class RegisterView(View):
    # 通过继承View，自动判断请求方法
    # 调用方法：View.as_view()
    "'用户注册'"
    def get(self, request):
        '''
       提供注册页面
       :param request: 请求对象r
       :return: 注册页面
        '''
        return render(request, 'register.html')
        #return HttpResponseBadRequest('注册功能尚未开放')
    
    def post(self, request):
        """
        1.接收数据
        2.验证数据
            2.1 参数是否齐全
            2.2 手机号的格式是否正确
            2.3 密码是否符合格式
            2.4 密码和确认密码要一致
            2.5 短信验证码是否和redis中的一致
        3.保存注册信息
        4.返回响应跳转到指定页面
        :param request:
        :return:
        """
        # 1、接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password')
        smscode = request.POST.get('sms_code')
        # 2、验证数据
        #   2.1、参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要参数')
        #   2.2、手机号的格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #   2.3、密码是否符合格式
        if not re.match(r'^[0-9A-Za-z{8, 20}]', password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')
        #   2.4、密码和确认密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s'%mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        # 3、保存注册信息
        # create_user 可以使用系统的方法对密码进行加密
        try:
            user = User.objects.create_user(username=mobile, mobile=mobile, password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')
        
        # 实现状态保持
        from django.contrib.auth import login
        login(request, user)
        # 4、返回响应跳转到指定页面
        #   4.1 redirect 进行重定向
        #   4.2 reverse 通过namespace:name 获取视图对应的路由
        response = redirect(reverse('home:index'))

        # 设置cookie信息，方便首页中用户信息展示的判断和用户信息的展示
        response.set_cookie('is_login', True)
        response.set_cookie('username', user.username, max_age=2*24*3600)
        return response

from django.http import HttpResponseBadRequest, HttpResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection

# 图片验证码
class ImageCodeView(View):
    
    def get(self, request):
        # 接收从前端传递过来的参数
        uuid = request.GET.get('uuid')
        # 判断参数是否为None
        if uuid is None:
            return HttpResponseBadRequest('请求参数错误')
        # 获取验证码内容和验证码图片的二进制数据
        text, image = captcha.generate_captcha()
        # 将图片内容保存到redis中并设置过期时间
        redis_conn = get_redis_connection('default')
        redis_conn.setex('image:%s' % uuid, 300, text)
        # 返回响应，将生成的图片以content_type为image/jpeg的形式返回给请求
        return HttpResponse(image, content_type='image/jpeg')

# 短信验证码
from django.http import JsonResponse
from utils.response_code import RETCODE
from random import randint
from libs.yuntongxun.sms import CCP
import logging
logger = logging.getLogger('django')

class SmsCodeView(View):

    def get(self, request):
        '''
        1.接收参数
        2.参数的验证
            2.1 验证参数是否齐全
            2.2 图片验证码的验证
                连接redis，获取redis中的图片验证码
                判断图片验证码是否存在
                如果图片验证码未过期，我们获取到之后就可以删除图片验证码
                比对图片验证码
        3.生成短信验证码
        4.保存短信验证码到redis中
        5.发送短信
        6.返回响应
        :param request:
        :return:
        '''
        # 1.接收参数 （查询字符串的形式传递过来）
        mobile=request.GET.get('mobile')
        image_code=request.GET.get('image_code')
        uuid=request.GET.get('uuid')
        # 2、校验参数
            # 2.1 验证参数是否齐全
        if not all([image_code, uuid, mobile]):
            return JsonResponse({'code': 'RETCODE.NECESSARYPARAMERR', 'errmsg':'缺少必传参数'})
        # 2.2 图片验证码的验证
        #创建连接到redis的对象，获取redis中的图片验证码
        redis_conn = get_redis_connection('default')
        #提取图形验证码
        redis_image_code = redis_conn.get('image:%s' % uuid)
        # 判断验证码是否存在
        if redis_image_code is None:
            #图形验证码过期
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg':'图形验证码失效'})
        #删除图形验证码，避免恶意测试图形验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')
        #对比图形验证码
        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg':'图形验证码有误'})

        # 生成短信验证码：生成6位数验证码
        sms_code = '%06d' % randint(0, 999999)
        #将验证码输出到控制台上，以方便调试
        logger.info(sms_code)
        # 保存短信验证码到redis中，并设置有效期
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        #发送短信验证码
        #CCP.send_template_sms(mobile, [sms_code, 5], 1)
        # 状态保持
        #返回响应
        return JsonResponse({'code':RETCODE.OK, 'errmsg':'发送短信成功'})

# 登录
class LoginView(View):

    def get(self, request):

        return render(request, 'login.html')
    
    def post(self, request):
        """
        1.接收参数
        2.参数的验证
            2.1 验证手机号是否符合规则
            2.2 验证密码是否符合规则
        3.用户认证登录
        4.状态的保持
        5.根据用户选择的是否记住登录状态来进行判断
        6.为了首页显示我们需要设置一些cookie信息
        7.返回响应
        :param request:
        :return:
        """

        # 1.接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        # 2.参数验证
        #   2.1 验证手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #   2.2 验证密码是否符合规则
        if not re.match(r'^[0-9A-Za-z{8, 20}]', password):
            return HttpResponseBadRequest('密码不符合规则')
        # 3.用户认证登录
        # 采用系统的自带的认证方法进行认证
        # 如果用户名和密码正确，返回user
        # 如果用户名或密码不正确，返回None
        from django.contrib.auth import authenticate
        # 默认的认证方法是针对于username字段进行用户名的判断
        # 当前的判断信息是手机号，故需要修改一下认证字段
        # 需要到User模型中进行修改，等测试出现问题的时候再修改
        user = authenticate(mobile=mobile, password=password)

        if user is None:
            return HttpResponseBadRequest('用户名或密码不正确')
        # 4.状态保持
        from django.contrib.auth import login
        login(request, user)
        # 5.根据用户选择进行是否记住登录状态的判断
        # 6.为了首页展示需要设置一些cookie信息
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))
        if remember != 'on': # 没有记住用户信息
            # 浏览器关闭之后
            request.session.set_expiry(0)
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14*24*3600)
        else:               # 记住用户信息
            #默认记住两周
            request.session.set_expiry(None)
            response.set_cookie('is_login', True, max_age=14*24*3600)
            response.set_cookie('username', user.username, max_age=14*24*3600)
        # 7.返回响应
        return response

# 退出登录
from django.contrib.auth import logout
class LogoutView(View):
    def get(self, request):
        # 1.session数据清除
        logout(request)
        response = redirect(reverse('home:index'))
        # 2.删除部分cookie数据
        response.delete_cookie('is_login')
        # 跳转到首页
        return response

# 忘记密码
class ForgetPasswordView(View):
    
    def get(self, request):
        return render(request, 'forget_password.html')
    
    def post(self, request):
        # 接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')

        # 判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('缺少必要参数')
        
        # 判断手机号是否合法
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('请输入正确的手机号码')
        
        # 判断密码是否合法
        if not re.match(r'^[0-9A-Za-z]{8,20}$',password):
            return HttpResponseBadRequest('请正确输入密码')
        
        # 判断两次输入的密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次输入的密码不一致')
        
        # 验证短信验证码
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期') 
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')
        # 根据手机号进行用户信息查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 如果没有查询出用户信息，则进行新用户的创建
            try:
                User.objects.create_user(username=mobile, mobile=mobile, password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后重试')
        else:
            # 修改用户密码
            user.set_password(password)
            user.save()

        # 跳转到登录页面
        response = redirect(reverse('users:login'))

        return response
        
# 判断用户是否登录
from django.contrib.auth.mixins import LoginRequiredMixin
#LoginRequiredMixin
# 如果用户未登录则会进行默认的跳转
# 默认的跳转链接为accounts/login/?next=/usercenter/，故需要在setting.py中修改默认跳转
class UserCenterView(LoginRequiredMixin, View):

    def get(self, request):
        # 获取登录用户的信息
        user = request.user
        # 组织用户信息
        context = {
            'username':user.username,
            'mobile':user.mobile,
            'avatar':user.avatar.url if user.avatar else None,
            'user_desc':user.user_desc
        }
        return render(request, 'center.html', context=context)
    def post(self,request):
        """
        1.接收参数
        2.将参数保存起来
        3.更新cookie中的username信息
        4.刷新当前页面（重定向操作）
        5.返回响应
        :param request:
        :return:
        """
        user=request.user
        # 1.接收参数
        username=request.POST.get('username',user.username)
        user_desc=request.POST.get('desc',user.user_desc)
        avatar=request.FILES.get('avatar')
        # 2.将参数保存起来
        try:
            user.username=username
            user.user_desc=user_desc
            if avatar:
                user.avatar=avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('修改失败，请稍后再试')
        # 3.更新cookie中的username信息
        # 4.刷新当前页面（重定向操作）
        response=redirect(reverse('users:center'))
        response.set_cookie('username',user.username,max_age=14*3600*24)

        # 5.返回响应
        return response

# 写博客
from home.models import ArticleCategory, Article
class WriteBlogView(LoginRequiredMixin, View):

    def get(self, request):
        # 查询所有分类模型
        categories = ArticleCategory.objects.all()

        context = {
            'categories':categories
        }

        return render(request, 'write_blog.html', context=context) 
    
    def post(self, request):
        '''
        1. 接收数据
        2. 验证数据
        3. 数据入库
        4. 跳转到指定页面（暂定首页）
        '''

        # 1.接收数据
        avatar = request.FILES.get('avatar')
        title = request.POST.get('title')
        category_id = request.POST.get('category')
        tags = request.POST.get('tags')
        sumary = request.POST.get('sumary')
        content = request.POST.get('content')
        user = request.user

        # 2. 验证数据
        #   2.1 验证参数是否齐全
        if not all([avatar, title, category_id, sumary, content]):
            return HttpResponseBadRequest('参数不全')
        #   2.2 判断分类id
        try:
            category=ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExit:
            return HttpResponseBadRequest('没有分类')
        # 3. 数据入库
        try:
            article=Article.objects.create(
                author = user,
                avatar = avatar,
                title = title,
                category = category,
                tags = tags,
                sumary = sumary,
                content = content,
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后重试')
        # 4. 跳转到指定页面
        return redirect(reverse('home:index'))

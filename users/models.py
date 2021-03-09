from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

# 用户信息
class User(AbstractUser):
    # 电话号码字段， unique为唯一字段
    mobile = models.CharField(max_length=20, blank=False, unique=True)
    # 头像信息
    avatar = models.ImageField(upload_to='avatar/%Y%m%d', blank=True)
    # 简介信息
    user_desc = models.CharField(max_length=500, blank=True)
    #修改认证字段为手机号
    USERNAME_FIELD = 'mobile'

    # 创建超级管理员必须输入的字段（不包括手机号和密码）
    REQUIRED_FIELDS = ['username', 'email']

    class Meta:
        db_table='tb_users' # 修改表名
        verbose_name = '用户管理' # admin后台显示
        verbose_name_plural = verbose_name #admin后台显示
    
    def __str__(self):
        return self.mobile
# coding: utf-8
from django import template


register = template.Library()


@register.filter
def get_range(value, args=None):
    """
    分页用
    """
    num = value+args
    if args < 0:
        return range(num, value)
    else:
        return range(value+1, num)

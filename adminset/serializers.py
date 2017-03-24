from adminset.models import UserPro as User
from rest_framework import routers, serializers, viewsets


# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ('url', 'name', 'email', 'is_staff')

class ServiceSerializer(serializers.ModelSerializer):
    pass

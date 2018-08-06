# coding: utf-8

"""
    User Data API

    No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)  # noqa: E501

    OpenAPI spec version: 
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class DeletedUserSiteCreate(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'deleted_user_id': 'str',
        'site_id': 'int',
        'deletion_requested_at': 'datetime',
        'deletion_requested_via': 'str',
        'deletion_confirmed_at': 'datetime',
        'deletion_confirmed_via': 'str'
    }

    attribute_map = {
        'deleted_user_id': 'deleted_user_id',
        'site_id': 'site_id',
        'deletion_requested_at': 'deletion_requested_at',
        'deletion_requested_via': 'deletion_requested_via',
        'deletion_confirmed_at': 'deletion_confirmed_at',
        'deletion_confirmed_via': 'deletion_confirmed_via'
    }

    def __init__(self, deleted_user_id=None, site_id=None, deletion_requested_at=None, deletion_requested_via=None, deletion_confirmed_at=None, deletion_confirmed_via=None):  # noqa: E501
        """DeletedUserSiteCreate - a model defined in Swagger"""  # noqa: E501

        self._deleted_user_id = None
        self._site_id = None
        self._deletion_requested_at = None
        self._deletion_requested_via = None
        self._deletion_confirmed_at = None
        self._deletion_confirmed_via = None
        self.discriminator = None

        self.deleted_user_id = deleted_user_id
        self.site_id = site_id
        if deletion_requested_at is not None:
            self.deletion_requested_at = deletion_requested_at
        if deletion_requested_via is not None:
            self.deletion_requested_via = deletion_requested_via
        if deletion_confirmed_at is not None:
            self.deletion_confirmed_at = deletion_confirmed_at
        if deletion_confirmed_via is not None:
            self.deletion_confirmed_via = deletion_confirmed_via

    @property
    def deleted_user_id(self):
        """Gets the deleted_user_id of this DeletedUserSiteCreate.  # noqa: E501


        :return: The deleted_user_id of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: str
        """
        return self._deleted_user_id

    @deleted_user_id.setter
    def deleted_user_id(self, deleted_user_id):
        """Sets the deleted_user_id of this DeletedUserSiteCreate.


        :param deleted_user_id: The deleted_user_id of this DeletedUserSiteCreate.  # noqa: E501
        :type: str
        """
        if deleted_user_id is None:
            raise ValueError("Invalid value for `deleted_user_id`, must not be `None`")  # noqa: E501

        self._deleted_user_id = deleted_user_id

    @property
    def site_id(self):
        """Gets the site_id of this DeletedUserSiteCreate.  # noqa: E501


        :return: The site_id of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: int
        """
        return self._site_id

    @site_id.setter
    def site_id(self, site_id):
        """Sets the site_id of this DeletedUserSiteCreate.


        :param site_id: The site_id of this DeletedUserSiteCreate.  # noqa: E501
        :type: int
        """
        if site_id is None:
            raise ValueError("Invalid value for `site_id`, must not be `None`")  # noqa: E501

        self._site_id = site_id

    @property
    def deletion_requested_at(self):
        """Gets the deletion_requested_at of this DeletedUserSiteCreate.  # noqa: E501


        :return: The deletion_requested_at of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: datetime
        """
        return self._deletion_requested_at

    @deletion_requested_at.setter
    def deletion_requested_at(self, deletion_requested_at):
        """Sets the deletion_requested_at of this DeletedUserSiteCreate.


        :param deletion_requested_at: The deletion_requested_at of this DeletedUserSiteCreate.  # noqa: E501
        :type: datetime
        """

        self._deletion_requested_at = deletion_requested_at

    @property
    def deletion_requested_via(self):
        """Gets the deletion_requested_via of this DeletedUserSiteCreate.  # noqa: E501


        :return: The deletion_requested_via of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: str
        """
        return self._deletion_requested_via

    @deletion_requested_via.setter
    def deletion_requested_via(self, deletion_requested_via):
        """Sets the deletion_requested_via of this DeletedUserSiteCreate.


        :param deletion_requested_via: The deletion_requested_via of this DeletedUserSiteCreate.  # noqa: E501
        :type: str
        """

        self._deletion_requested_via = deletion_requested_via

    @property
    def deletion_confirmed_at(self):
        """Gets the deletion_confirmed_at of this DeletedUserSiteCreate.  # noqa: E501


        :return: The deletion_confirmed_at of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: datetime
        """
        return self._deletion_confirmed_at

    @deletion_confirmed_at.setter
    def deletion_confirmed_at(self, deletion_confirmed_at):
        """Sets the deletion_confirmed_at of this DeletedUserSiteCreate.


        :param deletion_confirmed_at: The deletion_confirmed_at of this DeletedUserSiteCreate.  # noqa: E501
        :type: datetime
        """

        self._deletion_confirmed_at = deletion_confirmed_at

    @property
    def deletion_confirmed_via(self):
        """Gets the deletion_confirmed_via of this DeletedUserSiteCreate.  # noqa: E501


        :return: The deletion_confirmed_via of this DeletedUserSiteCreate.  # noqa: E501
        :rtype: str
        """
        return self._deletion_confirmed_via

    @deletion_confirmed_via.setter
    def deletion_confirmed_via(self, deletion_confirmed_via):
        """Sets the deletion_confirmed_via of this DeletedUserSiteCreate.


        :param deletion_confirmed_via: The deletion_confirmed_via of this DeletedUserSiteCreate.  # noqa: E501
        :type: str
        """

        self._deletion_confirmed_via = deletion_confirmed_via

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, DeletedUserSiteCreate):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

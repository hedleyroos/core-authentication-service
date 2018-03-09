from django.conf import settings
from django.forms import HiddenInput


def update_form_fields(form, required=None, hidden=None, validators=None, fields_data=None):
    """Update form fields and widgets.

    form --  Instance of a form.
    required -- list of fields to toggle required for.
    hidden -- list of fields to hide.
    validators -- a dictionary
        {
            "<fieldname>": [<list of validators>]
        }
    fields_data -- a dictionary
        {
            "<fieldname>": {
                "attributes": {
                    <attribute>: <value>
                },
            }
        }

    Helper method for setting field and widget attributes, can
    be used for any form instance. Sets attributes on both fields and widgets.
    """
    required = required or []
    hidden = hidden or []
    validators = validators or {}
    fields_data = fields_data or {}

    # Mark fields as required on both the form and widget
    for field in required:
        form.fields[field].required = True
        form.fields[field].widget.is_required = True

    # Mark fields as hidden on the widget
    for field in hidden:
        form.fields[field].widget = HiddenInput()

    # Set validators on fields.
    for field, data in validators.items():
        form.fields[field].validators = data

    # Update field and widget attributes.
    for field, data in fields_data.items():
        if data.get("attributes", None):
            widget = form.fields[field].widget
            field = form.fields[field]

            # Special case, allow for the assignment of a different input type.
            if data["attributes"].get("type"):
                widget.input_type = data["attributes"].pop(
                    "type", widget.input_type
                )

            # Widgets for the most part make use of a dictionary structure, so
            # just update the dictionary blindly.
            widget.attrs.update(data["attributes"])

            # Fields make use of instance attributes, so it requires a
            # different approach.
            for attr, val in data["attributes"].items():
                setattr(field, attr, val)


def set_listing_limit(limit):
    """ Ensures the limit is within bounds or sets the default limit if no limit
    was specified.
    :param limit: Amount of objects to return.
    :return: Either the minimum, maximum or the default limit.
    """
    if limit:
        limit = int(limit)
        limit = limit if limit <= settings.MAX_LISTING_LIMIT else \
            settings.MAX_LISTING_LIMIT
        limit = limit if limit >= settings.MIN_LISTING_LIMIT else \
            settings.MIN_LISTING_LIMIT
        return limit
    return settings.DEFAULT_LISTING_LIMIT


def strip_empty_optional_fields(object_dict):
    """ We do not need to add fields that contain None or "" to the response,
    so we strip those fields out of the response. To do this, we iterate over
    the fields in the input dictionary and check that the value isn't, what we
    consider, empty. If a field has a value, add that field and value to the
    output dictionary.
    :param object_dict: Input dictionary containing possible empty fields.
    :return: Output dictionary containing only fields that have values.
    """
    result = {}
    for field in object_dict:
        if object_dict[field] is not None and object_dict[field] is not "":
            result[field] = object_dict[field]
    return result

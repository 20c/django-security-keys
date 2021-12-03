import os

from django.conf import settings

import tests.project.settings
from tests.fixtures import *

_settings = {
    k: v
    for k, v in tests.project.settings.__dict__.items()
    if (not k.startswith("_") and k.isupper())
}

# settings.configure(**_settings)

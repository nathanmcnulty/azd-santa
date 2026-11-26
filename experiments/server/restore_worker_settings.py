"""Use the reviewed Zentral settings with a separate recovery observer."""

from copy import deepcopy

from server import settings

globals().update({name: value for name, value in vars(settings).items() if name.isupper()})
DATABASES = deepcopy(settings.DATABASES)
if set(DATABASES) != {'default'}:
    raise ValueError('Unexpected database aliases in the recovery worker')
DATABASES['observer'] = deepcopy(DATABASES['default'])

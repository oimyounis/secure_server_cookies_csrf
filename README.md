# Secure Server

### Generate New Secret

```python

import random
import string

choices = ''.join([string.ascii_lowercase, string.digits, '!@#$%^&*(-_=+)'])
''.join(random.SystemRandom().choice(choices) for i in range(50))
```

### Change API_MIDDLEWARE_CHARS in config.py

* Generate new set of characters
```python
import random
import string

choices = ''.join([string.ascii_letters, string.digits, '!$%&*'])
NEW_SET = ''.join(random.SystemRandom().choice(choices) for i in range(10))
```

* Set the API_MIDDLEWARE_CHARS setting
```python
# Replace NEW_SET with the generated string

API_MIDDLEWARE_CHARS = tuple(NEW_SET)
```

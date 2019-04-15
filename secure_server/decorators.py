excluded_funcs = []


class reqid_check_exempt(object):
    def __init__(self, func):
        self.func = func
        excluded_funcs.append(str(self.func).split(' ')[1])

    def __call__(self, request, *args, **kwargs):
        return self.func(self=None, request=request, *args, **kwargs)

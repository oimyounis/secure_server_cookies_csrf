excluded_funcs = []


class reqid_check_exempt:
    def __init__(self, func):
        print(func)
        self.func = func
        excluded_funcs.append(str(self.func).split(' ')[1])

    def __call__(self, request, *args, **kwargs):
        print('[reqid_check_exempt] __call__', excluded_funcs)
        return self.func(self=None, request=request, *args, **kwargs)

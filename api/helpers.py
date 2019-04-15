import re


def get_data(request, reduce_exclude=(), has_array_of_obj=False, array_as_obj=False):
    data = {**request.data, **request.FILES, **request.GET}
    items = data.copy().items()
    for key, value in items:
        if has_array_of_obj and any(char in key for char in ('[', ']')):
            field_name = re.findall(r'(^\w+)', key)[0]
            groups = re.findall(r'\[(\w+)\]', key)

            if re.match(r'\d+', groups[0]):
                groups[0] = int(groups[0])
                if len(groups) > 1:
                    if field_name not in data:
                        data[field_name] = []

                    diff = groups[0] + 1 - len(data[field_name])
                    if diff > 0:
                        for _ in range(diff):
                            data[field_name].append({})

                    if not isinstance(data[field_name][groups[0]], dict):
                        data[field_name][groups[0]] = {}

                    data[field_name][groups[0]][groups[1]] = _reduce(value)
                elif len(groups) == 1:
                    if field_name not in data:
                        if not array_as_obj:
                            data[field_name] = []
                        else:
                            data[field_name] = {}

                    if not array_as_obj:
                        data[field_name].append(_reduce(value))
                    else:
                        data[field_name][groups[0]] = _reduce(value)

            del data[key]
        else:
            if isinstance(value, list) and len(value) == 1 and key not in reduce_exclude:
                data[key] = _reduce(value)

    return data


def _reduce(value):
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


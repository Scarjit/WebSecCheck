import json


def jsonify(obj) -> str:
    xdata = None
    if type(obj) == int:
        xdata = str(obj)
    elif type(obj) == str:
        xdata = obj
    elif "to_dict" in dir(obj):
        xdata = json.dumps(obj.to_dict(), indent=4, sort_keys=True)
    elif type(obj) == dict:
        xdata = json.dumps(obj, indent=4, sort_keys=True)
    elif type(obj) is None or obj is None:
        xdata = json.dumps({})
    else:
        print(f"Cannot format {type(obj)} !")
        xdata = obj
    return xdata
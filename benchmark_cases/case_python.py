def add_item(item, items=[]):
    items.append(item)
    return items

def parse(v):
    try:
        return int(v)
    except:
        return 0

def ratio(a):
    return a / 0

def check(v):
    return v == None

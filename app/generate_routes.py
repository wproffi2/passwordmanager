import os

file_name = os.path.dirname(os.path.realpath(__file__))


file_name = os.path.join(file_name, 'app.py')

with open(file_name) as fp:
    lines = fp.readlines()


x = []
for line in lines:
    if '@application' in line:
        new_line = line[20:]
        x.append(new_line)

routes = []
for line in x:
    for i, s in enumerate(line):
        if s == "'":
            route = line[:i]
            routes.append(route)
            break

for route in routes:
    print(route)
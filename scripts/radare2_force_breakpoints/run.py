import r2pipe

r2 = r2pipe.open("!#pipe")

functions = r2.cmdj("aflj")

for function in functions:
    address = function["offset"]
    print("break at {}".format(hex(address)))
    r2.cmd("db {}".format(address))
    r2.cmd("dbte {}".format(address))
    r2.cmd("dbc {} db-{}".format(address, address))

print('Set continue on break...')
print("Done! you can start the debugger")

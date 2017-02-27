import claripy

solver = claripy.Solver()

var = claripy.BVS("<name>", 32)

solver.add(var <= 20)

solver.eval(var, 3)[0]

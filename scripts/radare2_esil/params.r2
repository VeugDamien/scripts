#conf binaire
o <name_of_binary>~prevent_display
e asm.arch = x86
e asm.bits = 64
e asm.esil = true

# conf esil
aei
#aeim 0x2000 0xffff
aeip
e io.cache=true
"e cmd.esil.intr=#!pipe python handlers.py"
e esil.gotolimit=0xffff
aec

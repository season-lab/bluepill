import idaapi
import json
import idc
import os

SEG_PROT_R = 4
SEG_PROT_W = 2
SEG_PROT_X = 1

cmd = 'vmmap'
try:
    mappings = json.loads(idc.send_dbg_command("vmmap"))
    for start, end, prot, pathname in mappings:
        # if pathname == "<no name>": continue # Why we should ignore mmapped mapges & co.?
        perms = 0
        if prot & SEG_PROT_R: perms |= idaapi.SEGPERM_READ
        if prot & SEG_PROT_W: perms |= idaapi.SEGPERM_WRITE
        if prot & SEG_PROT_X: perms |= idaapi.SEGPERM_EXEC
        name = os.path.basename(pathname)
        sclass = "DATA" # TODO recognize automatically sclass
        idaapi.add_segm(0, start, end, name, sclass)
  			idc.set_segm_attr(start, SEGATTR_PERM, perms)
			  idc.set_segm_attr(start, SEGATTR_ES, 0)
			  idc.set_segm_attr(start, SEGATTR_CS, 0)
			  idc.set_segm_attr(start, SEGATTR_SS, 0)
			  idc.set_segm_attr(start, SEGATTR_DS, 0)
			  idc.set_segm_attr(start, SEGATTR_FS, 0)
			  idc.set_segm_attr(start, SEGATTR_GS, 0)
except:
	#self.AddLine(idaapi.COLSTR("Debugger is not active or does not export send_dbg_command()", idaapi.SCOLOR_ERROR))
	print ("Debugger is not active or does not export send_dbg_command()")



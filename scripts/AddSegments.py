import idaapi
import idc

cmd = 'vmmap'
try:
	r = idc.SendDbgCommand(cmd)#Eval('SendDbgCommand("%s");' % cmd).split("\n")
	r = r.splitlines()
	for s in r:
		s = s.lstrip("[")
		s = s.rstrip("]")
		str = s.split(",")
		if str[3].strip("\"") != "<no name>":
			sn = str[3].split("\\")
			idaapi.add_segm(0, int(str[0]), int(str[1]), sn[len(sn)-1], "DATA")
			SetSegmentAttr(int(str[0]), SEGATTR_PERM, int(str[2]))
			SetSegmentAttr(int(str[0]), SEGATTR_ES, 0)
			SetSegmentAttr(int(str[0]), SEGATTR_CS, 0)
			SetSegmentAttr(int(str[0]), SEGATTR_SS, 0)
			SetSegmentAttr(int(str[0]), SEGATTR_DS, 0)
			SetSegmentAttr(int(str[0]), SEGATTR_FS, 0)
			SetSegmentAttr(int(str[0]), SEGATTR_GS, 0)
			
except:
	#self.AddLine(idaapi.COLSTR("Debugger is not active or does not export SendDbgCommand()", idaapi.SCOLOR_ERROR))
	print "Debugger is not active or does not export SendDbgCommand()"
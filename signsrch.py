#!/usr/bin/env python
# -*- coding: utf-8 -*-

from idaapi import *
import codecs
import time
import os

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def load_signatures():
    import xml.etree.ElementTree as ET

    db = idadir("plugins/signsrch.xml")
    if not os.path.isfile(db):
        db = os.path.join(get_user_idadir(), "plugins/signsrch.xml")
    root = ET.parse(db).getroot()

    signature = []
    for p in root:
        # <p t="name [64.le rev.64&amp;]">
        name, data = p.attrib['t'].split(" [")
        bits, endian, size = data[:-1].split(".")

        if "&" in size:
            if bits == "float":
                bits = 32
            elif bits == "double":
                bits = 64
            else:
                bits = int(bits)

        signature.append({
            "name": name,
            "bits": bits,
            "endian": endian,
            "size": size,
            "data": codecs.decode(p.text, ('hex')),
        })

    return signature

class Chooser(Choose):
    def __init__(self, items):
        Choose.__init__(self, "Signsrch", [["Address", 20], ["Label", 80]], embedded=False)
        self.items = items
        self.icon = 160

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        addr, label = self.items[n]
        seg_name = get_segm_name(getseg(addr))
        if seg_name:
            return ["%s:%X" % (seg_name, addr), label]
        else:
            return ["unknown:%X" % addr, label]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        jumpto(self.items[n][0])

class signsrch_t(plugin_t):
    flags = PLUGIN_PROC
    comment = "Signsrch"
    help = ""
    wanted_name = "Signsrch"
    wanted_hotkey = ""

    def init(self):
        print("Signsrch (Python Version) (v1.0) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        ignored = ["be", "le"][cvar.inf.is_be()]
        signatures = [s for s in load_signatures() if s["endian"] != ignored]

        if not signatures:
            print("No signature loaded, Aborted")
            return
        print("%d signatures loaded" % len(signatures))

        # Scan every segments
        start_time = time.time()

        found = []
        for i in range(get_segm_qty()):
            seg = getnseg(i)
            seg_name = get_segm_name(seg)
            seg_class = get_segm_class(seg)
            if seg.type in (SEG_XTRN, SEG_GRP, SEG_NULL, SEG_UNDF, SEG_ABSSYM, SEG_COMM, SEG_IMEM,):
                print("Skipping segment: %s, %s" % (seg_name, seg_class))
                continue

            print("Processing segment: %s, %s, 0x%08X - 0x%08X, %dbytes " % (seg_name, seg_class, seg.start_ea, seg.end_ea, seg.size()))
            bytes = get_bytes(seg.start_ea, seg.size())
            for sig in signatures:
                ea = None
                if "&" in sig["size"]:
                    bits = sig["bits"]
                    idx = 0
                    for s in chunks(sig["data"], bits // 8):
                        idx = bytes.find(s, idx)
                        if idx == -1:
                            ea = None
                            break

                        if ea == None:
                            ea = seg.start_ea + idx

                        idx += bits // 8
                else:
                    idx = bytes.find(sig["data"])
                    if idx != -1:
                        ea = seg.start_ea + idx

                if ea != None: # found
                    name = sig["name"]
                    found.append([ea, name])
                    print("Found %s @ 0x%X" % (name, ea))

                    # Add comment
                    cmt = get_cmt(ea, True)
                    if not cmt:
                        set_cmt(ea, '<Signsrch> "%s"' % name, True)
                    elif "Signsrch" not in cmt:
                        set_cmt(ea, cmt + ' <Signsrch> "%s"' % name, True)

        print("Found %d matches in %s seconds" % (len(found), time.time() - start_time))

        if found:
            ch = Chooser(found)
            ch.Show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return signsrch_t()


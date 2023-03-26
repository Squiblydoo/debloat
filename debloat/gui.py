from tkinter import *
from tkinterdnd2 import DND_FILES, TkinterDnD
import pefile
import threading
#from dotnetfile import DotNetPE
from pathlib import Path 
import tkinter.scrolledtext as st
from functools import partial
import time
import re
from typing import Tuple, Optional, Any
from processor import process_pe

class MainWindow(TkinterDnD.Tk):
    def __init__(self) -> None:
        TkinterDnD.Tk.__init__(self)
        self.title("Debloat")
        ## I removed the Tkinter Icon since it didn't work on most platforms and just caused more problems than necessary.
        self.geometry("600x600")

        #Label and PathBox
        self.pathboxLabel = Label(self, text="Drag and drop file onto text bar.")
        self.pathboxLabel.pack()
        self.pathbox = Entry(self, width=150)
        self.pathbox.pack(padx=20, pady=20)
        self.pathbox.drop_target_register(DND_FILES)
        self.pathbox.dnd_bind("<<Drop>>", self.processFileEntry)

        # Button to process file
        self.processFileButton = Button(self, text="Process file", command=self.processAndOutput)
        self.processFileButton.pack(pady=10)

        #Scrollbox for output
        self.outputScrollbox = st.ScrolledText(self, width=100, height=100)
        self.outputScrollbox.pack(padx=20, pady=20)

    def clearPathbox(self):
        self.pathbox.delete(0,"end")

    def outputScrollboxHandler(self, message):
        outputThread = threading.Thread(self.outputScrollbox.insert(INSERT, message))
        outputThread.start()

    def processFileEntry(self, event):
        self.pathbox.insert("end", event.data)
        filePath = self.pathbox.get()
        if filePath[0] == '{' and filePath[-1] == '}':
            filePath = filePath[1:-1]
            self.pathbox.delete(0,"end")
            self.pathbox.insert(0, filePath) 

    def processAndOutput(self):
        start_time = time.time()
        filepath = Path(self.pathbox.get())
        self.outputScrollboxHandler("Processing. Please wait.\n")

        try:
            pe = pefile.PE(filepath)
        except Exception:
            self.outputScrollboxHandler("Provided file is not an executable! Please try again with an executable. Maybe it needs unzipped?\n")
            self.clearPathbox()
            return

        out_path = filepath.parent / f"{filepath.stem}_patched{filepath.suffix}"
        process_pe(pe, out_path=str(out_path), log_message=lambda x: self.outputScrollboxHandler(x + "\n"))
        self.outputScrollboxHandler("-----Processessing took %s seconds ---\n" % round((time.time() - start_time), 2))
        self.clearPathbox()


def main() -> None:
    root = MainWindow()
    root.mainloop()


if __name__== "__main__":
    main()

"""This file handles all GUI components."""
import os
import time
from pathlib import Path 
from tkinter import *
import tkinter.scrolledtext as st
from typing import Tuple, Optional, Any
from tkinterdnd2 import DND_FILES, TkinterDnD
import pefile
import debloat.processor
from debloat.processor import DEBLOAT_VERSION
from debloat.processor import RESULT_CODES

class MainWindow(TkinterDnD.Tk):
    def __init__(self) -> None:
        '''Define main GUI window.'''
        TkinterDnD.Tk.__init__(self)
        self.title("Debloat " + DEBLOAT_VERSION)
        # I removed the Tkinter Icon since it didn't work on most 
        # platforms and just caused more problems than necessary.
        self.geometry("600x600")

        # Label and PathBox for the main function of program.
        self.pathbox_Label = Label(self, \
                                   text="Drag and drop file onto text bar.")
        self.pathbox_Label.pack()
        self.pathbox = Entry(self, width=150)
        self.pathbox.pack(padx=20)
        self.pathbox.drop_target_register(DND_FILES)
        self.pathbox.dnd_bind("<<Drop>>", self.process_entry)

        # Define button that will be used to the process file.
        self.process_button = Button(self, \
                                     text="Process file", \
                                     command=self.process)
        self.process_button.pack(pady=10)

        # Safe processing value and checkbox: Maybe not even needed?
        self.unsafe_processing = BooleanVar(value=False)
        self.unsafe_checkbox = Checkbutton(self,
                                        text="Check to run last ditch effort processing",
                                         variable=self.unsafe_processing)
        self.unsafe_checkbox.pack()

        self.cert_preservation = BooleanVar(value=False)
        self.cert_checkbox = Checkbutton(self, 
                                        text="Preserve Cert. Cert will be invalid but informational.",
                                        variable=self.cert_preservation)
        self.cert_checkbox.pack()

        

        # Define Scrollbox for output of program.
        self.output_scrollbox = st.ScrolledText(self, 
                                                width=100, 
                                                height=100,
                                                wrap=WORD)
        self.output_scrollbox.pack(padx=20, pady=20)

    def clear_pathbox(self) -> None:
        '''Clear any text in the pathbox.'''
        self.pathbox.delete(0,"end")

    def output_scrollbox_handler(self, message: str, end = "\n", flush=True) -> None:
        '''Insert messages in the textbox.'''
        self.output_scrollbox.insert(INSERT, message + end)
        self.update()

    def process_entry(self, event: Any) -> None:
        '''Check and update user provided file path.'''
        self.pathbox.insert("end", event.data)
        file_path = self.pathbox.get()
        if file_path[0] == '{' and file_path[-1] == '}':
            file_path = file_path[1:-1]
            self.pathbox.delete(0,"end")
            self.pathbox.insert(0, file_path) 

    def process(self) -> None:
        '''Process the file at the user provided path.'''
        start_time = time.time()
        file_path = Path(self.pathbox.get())
        self.output_scrollbox_handler("Processing. Please wait.")
        try:
            with open(file_path, "rb") as bloated_file:
                pe_data = bloated_file.read()
            pe = pefile.PE(data=pe_data, fast_load=True)
        except Exception:
            self.output_scrollbox_handler('''
Provided file is not an executable! Please try again 
with an executable. Maybe it needs unzipped?''')
            self.clear_pathbox()
            return
        file_size = os.path.getsize(file_path)
        out_path = file_path.parent \
            / f"{file_path.stem}_patched{file_path.suffix}"

        result_code = debloat.processor.process_pe(pe,  out_path, 
                                     self.unsafe_processing.get(), 
                                     self.cert_preservation.get(),
                   log_message=self.output_scrollbox_handler,
                   beginning_file_size=file_size)
        self.output_scrollbox_handler("Tactic identified: " , RESULT_CODES.get(result_code) +"\n")
        self.output_scrollbox_handler("-----Processing took %s seconds ---\n" \
                                    % round((time.time() - start_time), 2))
        self.clear_pathbox()

def main() -> None:
    root = MainWindow()
    root.mainloop()

if __name__== "__main__":
    main()

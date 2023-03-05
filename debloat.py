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


## NumberOfBytesHumanRepresetnation was reused from Didier Steven's publicly shared pecheck
def NumberOfBytesHumanRepresentation(value):
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

class processor():
    def checkFileFormat(filepath):
        with open(filepath, 'rb') as checker:
            return checker.read(2) == "MZ"

    def handleSignatureAbnormality(signatureAddress, signatureSize, beginningFileSize):
        # If the signatureAddress is 0, there was no original signature.
        ## We are setting the signature address to the filesize in order to skip the next check.
        if signatureAddress == 0:
            signatureAddress = beginningFileSize

        ### Check to see if there is data after the signature; if so, it is junk data
        if beginningFileSize > (signatureAddress + signatureSize):
            # If abnormality is identified, return True
            return 1
        # If abnormality is not identified, return False
        return 0

    def writePatchedFile(filepath, pe, endOfRealData):                  
        ## All file modification should be done at this point:

            newPEName = str(filepath.parent) +"/"+ str(filepath.stem) + '_patched' + str(filepath.suffix)
            with open(newPEName, 'wb') as writer:
                writer.write(pe.write()[:endOfRealData])
                finalFileSize = len(pe.write()[:endOfRealData])
                return finalFileSize, newPEName
                
    def checkForPacker(pe):
        packerHeader = pe.write()[pe.get_overlay_data_start_offset():pe.get_overlay_data_start_offset() + 30]
        ## TODO This section is being expanded to account for multiple types of packers.
        ## Packers store some important information in the overlay that we need to preserve. The intention here is to
        ## find the end of the Packer content based on headers. This may result in specific rules for specific headers
        ## or may end up requiring a genernic method to handle different file types.
        packerHeaderMatch = re.search(rb"^.\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst", packerHeader)
        if packerHeaderMatch:
            print("Nullsoft Header found.\n")
            
            nullSoftInstallerSize = int.from_bytes(packerHeader[18:21], "big")
            return nullSoftInstallerSize
        return 0

    def findLastSection(pe):
        lastSection = None
        for section in pe.sections:
            if lastSection is None or section.PointerToRawData > lastSection.PointerToRawData:
                lastSection = section
        return lastSection

    def removeSignature(pe): 
        signatureAddress = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        signatureSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
        return signatureAddress, signatureSize

    def processFile():
        pass

class main_window(TkinterDnD.Tk):
    def __init__(self):
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
        #fileForProcessing = partial(processor.processFile, self.pathbox.get())
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
            filePath=filePath[1:-1]
            self.pathbox.delete(0,"end")
            self.pathbox.insert(0, filePath) 

    def processAndOutput(self):
        
        start_time = time.time()
        filepath = Path(self.pathbox.get())
        self.outputScrollboxHandler("Processing. Please wait.\n")

        ##Initial Processsing
        try:
            pe = pefile.PE(filepath)
        except:
            self.outputScrollboxHandler("Provided file is not an executable! Please try again with an executable. Maybe it needs unzipped?\n")
            self.clearPathbox()
        beginningFileSize = len(pe.write())
        beginningFileSizeMB = NumberOfBytesHumanRepresentation(beginningFileSize)

        # We are using the variable "endOfRealData" and are reassigning the value based on our analysis.
        # We are assigning it now in case we are unable to reduce the binary size for any reason.
        endOfRealData = beginningFileSize
        self.outputScrollboxHandler("Beginning File size: " + beginningFileSizeMB + ".\n")

        ### Remove Signature and modify size of Optional Header Security entry.
        signatureAddress, signatureSize = processor.removeSignature(pe)
        signatureAbnormality = processor.handleSignatureAbnormality(signatureAddress, signatureSize, beginningFileSize)
        if signatureAbnormality:
            self.outputScrollboxHandler("We detected data after the signature. This is abnormal.\nRemoving signature and extra data...\n")
            endOfRealData = signatureAddress

        ## Handle Overlays: this includes packers and overlays which are completely junk
        elif pe.get_overlay_data_start_offset() and signatureSize < len(pe.get_overlay()):
            self.outputScrollboxHandler("An overlay was detected. Checking for known packer.\n")
            if processor.checkForPacker(pe):
                self.outputScrollboxHandler("Packer identified")
            else:
                self.outputScrollboxHandler("No use of packer identified. Removing whole overlay...\n")
                lastSection = processor.findLastSection(pe)
                endOfRealData = lastSection.PointerToRawData + lastSection.SizeOfRawData 
        

        ## Handle bloated sections
        ## TODO: break up into functions
        else:
            ### In order to solve some use cases, we will find the biggest section within the binary.
            biggestSection = None

            for section in pe.sections:
                #if lastSection is None or section.PointerToRawData > lastSection.PointerToRawData:
                sectionName = section.Name.decode()
                sectionEntropy = section.get_entropy()
                self.outputScrollboxHandler("Section "  + sectionName) 
                self.outputScrollboxHandler(" Entropy: " + str(round(sectionEntropy, 4)) + " " )
                self.outputScrollboxHandler("Size of section: " + NumberOfBytesHumanRepresentation(section.SizeOfRawData) +".\n")


                ## The use cases covered by this section are at the end of the binary.
                ## In my experience, the bloated sections are usually at the end unless they are bloat from .NET Resources.
                if sectionEntropy < 0.09 and section.SizeOfRawData > 100000:
                    self.outputScrollboxHandler("Entropy of section is exteremely low.\n This is indicative of a bloated section.\n Removing bloated section...\n")
                    
                    #Get the size of the section.
                    sectionEnd = section.PointerToRawData + section.SizeOfRawData

                    #If the entropy is simply 0.00, there is no data to be missed, we won't waste CPU and just drop the whole thing.
                    if sectionEntropy == 0.00:
                        ## We won't waste any time. We will just drop the whole thing. Though to play it safe, we will
                        ## leave 100 bytes in the section. And thus mark the end of the binary as the beginning of the last
                        ## section + 100.
                        sectionBytesToRemove = section.SizeOfRawData - 100
                        endOfRealData = section.PointerToRawData + 100
                    
                    ## If the section has low entropy we'll try to determine how much is junk.
                    else:
                        sectionData = pe.write()[section.PointerToRawData:sectionEnd]
                        sectionEnd = section.PointerToRawData + section.SizeOfRawData
                        sectionData = pe.write()[section.PointerToRawData:sectionEnd]
                        revertedSectionData = sectionData[::-1]
                        junkMatch = re.search(rb"(.)\1{100,}", revertedSectionData)
                        if not junkMatch:
                            delta_last_non_zero = len(revertedSectionData)
                        else:
                            delta_last_non_zero = len(revertedSectionData) - junkMatch.end(0)
                        
                        sectionBytesToRemove = beginningFileSize - (section.PointerToRawData + delta_last_non_zero + 1)
                        endOfRealData = section.PointerToRawData + delta_last_non_zero + 1

                    ## Fix last section header, SizeOfRawData, SizeOfImage.
                    section.Misc_VirtualSize -= sectionBytesToRemove
                    section.SizeOfRawData -= sectionBytesToRemove
                    pe.OPTIONAL_HEADER.SizeOfImage -= sectionBytesToRemove 



                ## Handle specific bloated sections
                if biggestSection == None:
                    biggestSection = section
                elif section.SizeOfRawData > biggestSection.SizeOfRawData:
                    biggestSection = section
                
            if biggestSection.Name.decode() == ".rsrc\x00\x00\x00":
                ## Get biggest resource or resources and drop them from the Resource table
                ## TODO: recalculate PE header in situations where the resource is not at the end of an executable.
                ## TODO: Handle other tomfoolery required when resource is not at end of executable.
                self.outputScrollboxHandler("Bloat was located in the resource section.\nRemoving bloat..\n")
                entryList = pe.DIRECTORY_ENTRY_RESOURCE.entries
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    if hasattr(resource_lang, 'data'):
                                        if resource_lang.data.struct.Size > 50000:
                                            ## If the resource is bloated, remove it with pop
                                            ## then subtract the size from the endOfRealData variable
                                            resource_type.directory.entries.pop()
                                            endOfRealData -= resource_lang.data.struct.Size
                                            pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size -= resource_lang.data.struct.Size 
                                            pe.sections[pe.sections.index(biggestSection)].SizeOfRawData -= resource_lang.data.struct.Size
                                            pe.sections[pe.sections.index(biggestSection)].Misc_VirtualSize -= resource_lang.data.struct.Size
                                            pe.sections[pe.sections.index(biggestSection)].section_max_addr -= resource_lang.data.struct.Size
                    pe.DIRECTORY_ENTRY_RESOURCE.entries[entryList.index(resource_type)] = resource_type
                            

            elif biggestSection.Name.decode() == ".text\x00\x00\x00":
                self.outputScrollboxHandler("Bloat was detected in the text section.\n")
                ## Data stored in the .text section is often a .NET Resource. The following checks
                ## to confirm it is .NET and then drops the resources.
                if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
                    self.outputScrollboxHandler("Bloat is likely in a .NET Resource\nThis use case cannot be processed at this time.\n")
                    
        ## All processing is done. Report results.
        if endOfRealData == beginningFileSize:
            self.outputScrollboxHandler("\nNo automated method for reducing the size worked.\nPlease consider sharing the sample for additional analysis.\nEmail: Squiblydoo@pm.me\nTwitter: @SquiblydooBlog.\n\n")
            self.clearPathbox()
        else:
            self.outputScrollboxHandler("Writing to file... \n")
            finalFileSize, newPEName = processor.writePatchedFile(filepath, pe, endOfRealData)
            finalFileSizeMB = NumberOfBytesHumanRepresentation(finalFileSize)
            reductionCalculation = round(((beginningFileSize - finalFileSize) / beginningFileSize) * 100, 2)
            self.outputScrollboxHandler("File was reduced by " + str(reductionCalculation) + "%.\n")
            self.outputScrollboxHandler("Final file size: " + finalFileSizeMB+ ".\n")
            self.outputScrollboxHandler("Processing complete.\nFile written to '" + str(newPEName) + "'.\n")
            self.clearPathbox()

       
        
        self.outputScrollboxHandler("-----Processessing took %s seconds ---\n" % round((time.time() - start_time),2))


def main():
    root = main_window()
    root.mainloop()

   
if __name__== "__main__":
    main()

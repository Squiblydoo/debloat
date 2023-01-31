from tkinter import *
from tkinterdnd2 import DND_FILES, TkinterDnD
import pefile
from pathlib import Path 
import tkinter.scrolledtext as st
import time
import re


def main():
    filePath = ""
    def drop_inside_path_box(event):
        pathbox.insert("end", event.data)
        filePath = pathbox.get()
        if filePath[0] == '{' and filePath[-1] == '}':
            filePath=filePath[1:-1]
            pathbox.delete(0,"end")
            pathbox.insert(0, filePath) 

    def processFile():
        start_time = time.time()
        outputScrollbox.insert(INSERT, "Processing. Please wait.\n")
        
        filePath = Path(pathbox.get())
        
        ## Check if file is an executable and process it accordingly.
        try:
            pe = pefile.PE(filePath)
        except: 
            outputScrollbox.insert(INSERT, "Provided file is not an executable! Please try again with an executable. Maybe it needs unzipped?\n")
            pathbox.delete(0,'end')
            
        beginningFileSize = len(pe.write())
        beginningFileSizeMB = round(((beginningFileSize / 1024) / 1024), 2)
        outputScrollbox.insert(INSERT, "Beginning File size: " + str(beginningFileSizeMB) + "MB .\n")
        ### Remove Signature and modify size of Optional Header Security entry.
        signatureAddress = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
        signatureSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
        
        # If the signatureAddress is 0, there was no original signature.
        ## We are setting the signature address to the filesize in order to skip the next check.
        if signatureAddress == 0:
            signatureAddress = beginningFileSize

        ### Check to see if there is data after the signature; if so, it is junk data
        if beginningFileSize > (signatureAddress + signatureSize):
            outputScrollbox.insert(INSERT, "!!!!!\nWe detected data after the signature. This is abnormal.\n!!!!!!\nRemoving signature and extra data...\n")
            endOfRealData = signatureAddress

        else:
           
            ### Calculate last section of binary.
            ### Calclulate the end of binary without the Offset
            ### This method does not account for file types with content in the Offset


            lastSection = None
            for section in pe.sections:
                #if lastSection is None or section.PointerToRawData > lastSection.PointerToRawData:
                lastSection = section
                sectionName = section.Name.decode()
                sectionEntropy = section.get_entropy()
                outputScrollbox.insert(INSERT, "Section "  + sectionName) 
                outputScrollbox.insert(INSERT, " Entropy: " + str(sectionEntropy) + ".\n" )
              
                if sectionEntropy < 0.09 and sectionEntropy > 0.01 and section.SizeOfRawData > 100000:
                    outputScrollbox.insert(INSERT, "Entropy of section is exteremely low.\n This is indicative of a bloated section.\n Removing bloated section...\n")
                    
                    # Using method provided by Malcat. Currently works for last section with null bytes.
                    # 1) We calculate very simply where the end of the section is.
                    # 2) We get the data from the final section and store it as "SectionData"
                    # 3) We reverse the section data and presumably the beginning of the section is not junk
                    # 4) We use regex to make a matching group based on null bytes. That match is calculated by 
                    #       subtracting the length of the match against the size of the revertedSectionData.
                    # 5) We then calculate a simple number of bytes to remove 
                    sectionEnd = section.PointerToRawData + section.SizeOfRawData
                    sectionData = pe.write()[section.PointerToRawData:sectionEnd]
                    revertedSectionData = sectionData[::-1]
                    junkMatch = re.search(rb"[^\x00]", revertedSectionData)
                    if not junkMatch:
                        delta_last_non_zero = len(revertedSectionData)
                    else:
                        delta_last_non_zero = len(revertedSectionData) - junkMatch.end(0)
                    
                    sectionBytesToRemove = beginningFileSize - (section.PointerToRawData + delta_last_non_zero + 1)

                    ## Fix last section header
                    section.Misc_VirtualSize -= sectionBytesToRemove
                    section.SizeOfRawData -= sectionBytesToRemove
                    pe.OPTIONAL_HEADER.SizeOfImage -= sectionBytesToRemove 

                    endOfRealData = section.PointerToRawData + delta_last_non_zero + 1




                
            endOfRealData = lastSection.PointerToRawData + lastSection.SizeOfRawData


        ## All file modification should be done at this point:
        ## Write the binary to the same directory as the original binary.
        outputScrollbox.insert(INSERT, "Writing to file... \n")
        newPEName = str(filePath.parent) +"/"+ str(filePath.stem) + '_patched' + str(filePath.suffix)
        with open(newPEName, 'wb') as writer:
            writer.write(pe.write()[:endOfRealData])
            finalFileSize = len(pe.write()[:endOfRealData])
            

        ## Tell the user it is done and the name of the new file.
        finalFileSizeMB = round(((finalFileSize / 1024 ) / 1024), 2)
        reductionCalculation = round(((beginningFileSizeMB - finalFileSizeMB) / beginningFileSizeMB) * 100, 2)
        outputScrollbox.insert(INSERT, "File was reduced by " + str(reductionCalculation) + "%.\n")
        outputScrollbox.insert(INSERT, "Final file size: " + str(finalFileSizeMB)+ "MB.\n")
        outputScrollbox.insert(INSERT, "Processing complete.\nFile written to '" + str(newPEName) + "'.\n")
        pathbox.delete(0,'end')
        outputScrollbox.insert(INSERT,"-----Processessing took %s seconds ---\n" % round((time.time() - start_time),2))
    
            
        



        #print(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress)




    root = TkinterDnD.Tk()
    root.title("Debloat")
    ## I removed the Tkinter Icon since it didn't work on most platforms and just caused more problems than necessary.
    root.geometry("600x600")

    #Label and PathBox
    pathboxLabel = Label(root, text="Drag and drop file onto text bar.")
    pathboxLabel.pack()
    pathbox = Entry(root, width=150)
    pathbox.pack(padx=20, pady=20)
    pathbox.drop_target_register(DND_FILES)
    pathbox.dnd_bind("<<Drop>>", drop_inside_path_box)

    # Button
    processFileButton = Button(root, text="Process file", command=processFile)
    processFileButton.pack(pady=10)

    #Scrollbox
    outputScrollbox = st.ScrolledText(root, width=100, height=100)
    outputScrollbox.pack(padx=20, pady=20)

    #Main Loop
    root.mainloop()

if __name__== "__main__":
    main()

import tkinter as tk
from tkinter import  filedialog
class imageEncrption:
    def __init__(self,master):
        self.master = master
        self.master.title("Image Encryption")
        self.master.geometry("200x160")

        b1=tk.Button(master,text="load image",command=self.encriptImage)
        b1.place(x=70,y=10)
        self.entry1=tk.Text(master,height=1,width=10)
        self.entry1.place(x=50,y=50)

    def encriptImage(self):
        file1=filedialog.askopenfile(mode='r',filetype=[('jpg file','*.jpg'),('png file','*.png')])
        if file1 is not None:
            fileName=file1.name
            key=self.entry1.get(1.0,tk.END)
            print(key)
            f1=open(fileName,'rb')
            image=f1.read()
            f1.close()
            image=bytearray(image)
            for index,value in enumerate(image):
                image[index]=value^int(key)
            fi1=open(fileName,'wb')
            fi1.write(image)
            fi1.close()

def main():
    root = tk.Tk()
    gui = imageEncrption(root)
    root.mainloop()

if __name__ == "__main__":
    main()
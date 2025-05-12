import ctypes


from tkinter import Tk, IntVar
import tkinter.ttk as ttk
import os
import shutil as sh
from PIL import Image


class Win:

    @staticmethod
    def msgbox(title, text, style: int = 0):
        """
        styles:
            0 : OK
            1 : OK      |   Cancel
            2 : Abort   |   Retry       |   Ignore
            3 : Yes     |   No          |   Cancel
            4 : Yes     |   No
            5 : Retry   |   Cancel
            6 : Cancel  |   Try Again   |   Continue

        Return:
            releted int value of the button pressed
        """
        return ctypes.windll.user32.MessageBoxW(0, title, text, style)




    @staticmethod
    def collect_images(window: bool = True, size: tuple = (1920, 1080)):
        DEFAULT_SP = 'Packages\\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\\LocalState\\Assets'
        spotdir = os.path.join(os.getenv('LOCALAPPDATA'), DEFAULT_SP)
        dest = os.path.join(os.getenv('USERPROFILE'),"Desktop", "SL-Wallpaper")
        if not os.path.exists(dest):
            os.mkdir(dest)
        # copy SP walpaper tree folder
        # try:
        #     shutil.copytree(spotdir, dest)
        # except FileExistsError:
        #     print('Invalid Name.')
        source_list = os.listdir(spotdir)
        if len(source_list) > 0:
            for i, f in enumerate(source_list):
                from_path = os.path.join(spotdir, f)
                to_path = os.path.join(dest, f + ".jpeg")
                while os.path.exists(to_path):
                    to_path = to_path + "#"
                sh.copy(from_path, to_path)
                with Image.open(to_path) as img:
                    img_size = img.size
                if img_size != size:
                    os.remove(to_path)
            # open dest folder
            os.startfile(dest)
            main.destroy()
            return os.listdir(dest)



# Gui
main = Tk()

main.title('SL Wallpaper Downloader')
main.resizable(False, False)

start_btn = ttk.Button(main, text='Start', command=Win.collect_images)

progress_bar = ttk.Progressbar(main, length=500)
lab1 = ttk.Label(main, justify='center',
                 text='Press START to collect and download all SPL Wallpapers')

lab1.pack(pady=5)
progress_bar.pack(padx=5,pady=5)
start_btn.pack(pady=5)

start_btn.focus()
main.mainloop()
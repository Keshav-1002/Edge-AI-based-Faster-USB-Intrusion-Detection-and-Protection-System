import os
import time
import math
import psutil
import threading
import pandas as pd
import onnxruntime as rt
import numpy as np
from tkinter import *
from tkinter import messagebox
from datetime import datetime

usb_path = None
usb_input_ds = None
malicious = None
stop_flag = threading.Event()

#list of suspicious extensions for flagging purpose
suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.vbs', '.js', '.cmd', '.ps1', '.jar', '.apk',
                    '.com', '.pyd', '.ax', '.mui']

root = Tk()
root.title("Edge-AI Based Faster USB ID & PS")
root.geometry("500x300")

def update_status(msg):
    status_label.config(text=f"Status: {msg}")
    root.update_idletasks()

def on_block_pressed():
    global usb_path
    log_usb_scan_result(usb_path, True, "Signature" if malicious else "Behavior", "Blocked")
    messagebox.showinfo("USB Blocked", "USB blocked. Please remove it.")
    root.destroy()

def on_ignore_pressed():
    global usb_path
    log_usb_scan_result(usb_path, True, "Signature" if malicious else "Behavior", "Ignored")
    messagebox.showinfo("USB Unmounted", "USB Unmounted due to security issue...\nPlease re-insert it.")
    root.destroy()

def on_usb_detected():
    status_label.config(text=f"Status : USB detected in drive - {usb_path}", fg="green")
    scan_button.pack(pady=10)

label_font = ("Arial", 14, "bold")
button_font = ("Arial", 12)
button_style = {"font": button_font, "bd": 2, "relief": "ridge", "bg": "light grey", 
                "activebackground": "dark grey"}


status_label = Label(root, text="Status : Checking for USB insertion...", font=label_font, fg="black")
status_label.pack(pady=30)

result_label = Label(root, text="", font=("Arial", 18), fg="black")
result_label.pack(pady=10)

scan_button = Button(root, text="Scan USB", command=lambda: threading.Thread(target=scan_usb).start(),
                     **button_style)
malware_buttons_frame = Frame(root, bg="light grey")
block_button = Button(malware_buttons_frame, text="Block\n(Recommended)", command=on_block_pressed,
                      **button_style)
continue_malware_button = Button(malware_buttons_frame, text="Ignore\n(Not Recommended)",
                                 command=on_ignore_pressed, **button_style)
continue_clean_button = Button(root, text="Finish", command=root.quit, **button_style)


def log_usb_scan_result(usb_name, infected, detection_type, action=None):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Infected" if infected else "Clean"
    log_line = f"USB Name: {usb_name} | {time_now} | Status: {status} | Detection: {detection_type}"
    
    if action:
        log_line += f" | User Action: {action}"
    
    log_line += "\n" 

    with open("keep_logs.txt", "a") as f:
        f.write(log_line)
        f.flush()

    print("Logged:", log_line.strip())

#func to get list of removable drives
def get_usb_drive_list():
    drives = []
    
    for d in psutil.disk_partitions(all=False):
        
        if 'removable' in d.opts:
            drives.append(d.device)
            
    return drives

#func to detect usb insertion
def detect_usb():
    global usb_path
    prev_usb_list = get_usb_drive_list()
    
    while True:
        time.sleep(1)
        curr_usb_list = get_usb_drive_list()
        new_usb = [usb for usb in curr_usb_list if usb not in prev_usb_list]
        
        if new_usb:
            usb_path = new_usb[0]
            root.after(0, on_usb_detected)
            return
        
        prev_usb_list = curr_usb_list


#func to calculate entropy using shannon formula
def get_entropy(file_path):
    
    try:
        
        with open(file_path, 'rb') as f:
            byte_arr = f.read()
            
        if len(byte_arr) == 0:
            return 0
        
        freq = {}
        
        for byte in byte_arr:
            freq[byte] = freq.get(byte, 0) + 1
            
        entropy = -sum((count / len(byte_arr)) * math.log2(count / len(byte_arr)) for count in freq.values())
        return entropy
    
    except:
        return 0

#func to extract features
def extract_features(path):
    global usb_input_ds
    data = []
    
    for root_dir, dirs, files in os.walk(path):
        
        for file in files:
            
            try:
                file_path = os.path.join(root_dir, file)
                size = os.path.getsize(file_path) / 1024
                _, ext = os.path.splitext(file)
                ext = ext.lower() if ext else '.none'
                ext_flag = 1 if ext in suspicious_exts else 0
                entropy = get_entropy(file_path)
                data.append([round(size, 2), ext_flag, entropy])
                
            except Exception as e:
                print(f"Error reading {file}: {e}")
                
    usb_input_ds = pd.DataFrame(data, columns=['filesize', 'extflag', 'entropy'])
    print("Features extracted.")

#func for behavior data
def monitor_usb_behavior(path,duration=10):
    behavior_log = {
        "read_bytes":0,
        "write_bytes":0,
        "file_open_count":0,
        "exe_run_attempts":0,
        "cmd_proc_count":0
    }

    start_time = time.time()
    opened_files = set()
    usb_drive_letter = path[:2].lower()

    while(time.time() - start_time < duration):
        
        if stop_flag.is_set():
            print("Behave scan stopped early",flush=True)
            return pd.DataFrame([[0,0,0,0,0]],columns=["read_bytes","write_bytes","file_open_count",
                                                    "exe_run_attempts","cmd_proc_count"])

        for proc in psutil.process_iter(['name','exe']):
            
            try:
                pname = proc.info['name']
                
                if pname and pname.lower() in ['cmd.exe','powershell.exe','terminal','cmd','powershell']:
                    behavior_log["cmd_proc_count"] += 1

                exe_path = proc.info['exe']
                
                if exe_path and exe_path.lower().startswith(usb_drive_letter):
                    behavior_log["file_open_count"] += 1
                    
                    if exe_path.lower().endswith(('.exe','.bat')):
                        behavior_log["exe_run_attempts"] += 1

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        try:
            disk_counters = psutil.disk_io_counters(perdisk=True)
            
            for disk, stats in disk_counters.items():
                
                if usb_drive_letter in disk.lower():
                    behavior_log["read_bytes"] += stats.read_bytes
                    behavior_log["write_bytes"] += stats.write_bytes

        except Exception as e:
            print("Disk reading error")

        time.sleep(0.3)

    return pd.DataFrame([[behavior_log["read_bytes"], behavior_log["write_bytes"],
                        behavior_log["file_open_count"],behavior_log["exe_run_attempts"],
                        behavior_log["cmd_proc_count"]]],columns=["read_bytes","write_bytes",
                        "file_open_count","exe_run_attempts","cmd_proc_count"])


#func to unmount usb
def unmount_usb(drive_letter):
    
    try:
        print(f"Unmounting {drive_letter}")
        os.system(f"mountvol {drive_letter} /p")
        print("USB unmounted.")
        
    except Exception as e:
        print(f"Unmount failed: {e}")

#func to get onnx pred
def pred_onnx(X):
    sess = rt.InferenceSession("bestAIModel.onnx")
    input_name = sess.get_inputs()[0].name
    pred_onx = sess.run(None, {input_name: X.astype(np.float32).values})[0]
    return int(any(pred_onx))

#func for behav scanning
def predict_behavior(path):
    update_status("Monitoring USB behavior...")
    behav_df = monitor_usb_behavior(path,10)
    sess = rt.InferenceSession("behavModel.onnx")
    input_name = sess.get_inputs()[0].name
    pred = sess.run(None,{input_name: behav_df.astype(np.float32).values})[0]
    print("Behav scan done")
    return int(pred[0])

#func to get ai predictions
def predict_usb():
    global malicious
    
    if usb_input_ds is None or usb_input_ds.empty:
        print("No data to predict")
        return False
    
    X = usb_input_ds[['filesize','extflag','entropy']]
    malicious = pred_onnx(X)
    update_status("Signature scanning completed.")
    print("Sign scan done")
    return malicious

#func for scanning usb
def scan_usb():
    status_label.config(text="Status : Hybrid scanning in progress...", fg="blue")
    scan_button.pack_forget()
    print("scanning started")
    extract_features(usb_path)
    behavior_result = [0]
    stop_flag.clear()

    def behavior_thread():
        print("Behavior thread working")
        behavior_result[0] = predict_behavior(usb_path)

    thread = threading.Thread(target=behavior_thread)
    thread.start()

    signature_result = predict_usb()
    update_status("Behavior scanning in progress...")

    if signature_result == 1:
        stop_flag.set()
        print("Stop flag is set")
        result = True
        update_status("Behavior scanning terminated.")

    else:
        thread.join()
        result = (behavior_result[0]==1)
        update_status("Behavior scanning completed.")

    unmount_usb(usb_path[:2])
    print("Both scan completed")
    update_status("Overall scanning completed.")
    root.after(1000, lambda: show_scan_result(result))

def show_scan_result(found_malware):
    global usb_path, malicious
    status_label.config(text="Status : Scan completed")
    
    if found_malware and malicious:
        result_label.config(text="⚠ Malware detected by Signature!", fg="red")
        log_usb_scan_result(usb_path, True, "Signature")
        show_malware_buttons()

    elif found_malware: 
        result_label.config(text="⚠ Suspicious activity detected by Behavior!", fg="red")
        log_usb_scan_result(usb_path, True, "Behavior")
        show_malware_buttons()
        
    else:
        result_label.config(text="✅ No malware found. USB is safe.", fg="green")
        log_usb_scan_result(usb_path, False, "Clean")
        continue_clean_button.pack(pady=10)

def show_malware_buttons():
    malware_buttons_frame.pack(pady=10)
    block_button.pack(side=LEFT, padx=5)
    continue_malware_button.pack(side=LEFT, padx=5)

threading.Thread(target=detect_usb).start()
root.mainloop()

import tkinter as tk
from tkinter import scrolledtext
import requests

API_KEY = '2b7ecf504f1a63cb6d0dd866a970c78fda63b6ac7930248a9aa96e7d7acea4dd'
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def check_url_reputation(url):
    try:
        params = {'apikey': API_KEY, 'resource': url}
        
        response = requests.get(VIRUSTOTAL_URL, params=params)

        result = response.json()

        if result['response_code'] == 1:

            if result['positives'] > 0:
                return f"Warning: The URL {url} has been flagged as spam or harmful by {result['positives']} services."
            else:
                return f"The URL {url} appears to be safe."
        else:
            return "Error: The URL was not found in the VirusTotal database."

    except Exception as e:
        return f"Error: {str(e)}"

def on_submit():
    user_input = input_box.get("1.0", tk.END).strip() 
    
    if user_input.lower() == "end": 
        root.quit() 
        return
    
    if user_input:
        response = check_url_reputation(user_input) 
        response_box.config(state=tk.NORMAL)  
        response_box.delete(1.0, tk.END) 
        response_box.insert(tk.END, response)  
        response_box.config(state=tk.DISABLED) 
    else:
        response_box.config(state=tk.NORMAL)
        response_box.delete(1.0, tk.END)
        response_box.insert(tk.END, "Please enter a valid URL.")
        response_box.config(state=tk.DISABLED)


root = tk.Tk()
root.title("URL Spam Checker Chatbot")
root.geometry("600x450")
root.configure(bg="#f4f4f4")  


title_font = ("Helvetica", 16, "bold")
text_font = ("Helvetica", 12)


title_label = tk.Label(root, text="URL Spam Checker Chatbot", font=title_font, bg="#f4f4f4", fg="#333333")
title_label.pack(pady=15)


input_frame = tk.Frame(root, bg="#f4f4f4")
input_frame.pack(pady=10)

instruction_label = tk.Label(input_frame, text="Enter a URL or type 'end' to exit:", font=text_font, bg="#f4f4f4", fg="#333333")
instruction_label.grid(row=0, column=0, padx=5)

input_box = tk.Text(input_frame, height=2, width=50, font=text_font, bg="#ffffff", fg="#333333", borderwidth=2, relief="solid")
input_box.grid(row=1, column=0, padx=5, pady=5)

submit_button = tk.Button(root, text="Check URL", command=on_submit, font=("Helvetica", 12), bg="#007BFF", fg="white", relief="flat", padx=10, pady=5)
submit_button.pack(pady=10)

response_box = scrolledtext.ScrolledText(root, height=10, width=70, state=tk.DISABLED, wrap=tk.WORD, font=text_font, bg="#ffffff", fg="#333333", borderwidth=2, relief="solid")
response_box.pack(pady=10)

root.mainloop()

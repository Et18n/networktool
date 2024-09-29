import tkinter as tk
from tkinter import scrolledtext
import requests

# Hugging Face API Key (replace with your own API key)
API_KEY = 'your_huggingface_api_key_here'

# URL for Hugging Face's Inference API (replace with a model hosted on Hugging Face, e.g., gpt2)
API_URL = "https://api-inference.huggingface.co/models/gpt2"

# Function to query the Hugging Face Inference API
def query_huggingface_api(text_input):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    data = {"inputs": text_input}
    response = requests.post(API_URL, headers=headers, json=data)
    return response.json()

# Function to get a response from the chatbot using Hugging Face API
def get_response(user_input):
    try:
        response = query_huggingface_api(user_input)
        return response[0]['generated_text']
    except Exception as e:
        return f"Error: {str(e)}"

# Function to handle user input and display response
def on_submit():
    user_input = input_box.get("1.0", tk.END).strip()  # Get input from the text box
    
    if user_input.lower() == "end":  # Check if the user typed "end"
        root.quit()  # Exit the program
        return
    
    if user_input:
        response = get_response(user_input)  # Get response from the chatbot
        response_box.config(state=tk.NORMAL)  # Enable the response box for writing
        response_box.delete(1.0, tk.END)  # Clear previous content
        response_box.insert(tk.END, response)  # Insert the response
        response_box.config(state=tk.DISABLED)  # Disable the response box to prevent manual input
    else:
        response_box.config(state=tk.NORMAL)
        response_box.delete(1.0, tk.END)
        response_box.insert(tk.END, "Please enter a valid question.")
        response_box.config(state=tk.DISABLED)

BG_GRAY = "#f5f6f7"
BG_COLOR = "#17202A"
TEXT_COLOR = "#EAECEE"

FONT = "Times"
FONT_BOLD = "Helvetica 13 bold"
# Create the main window
root = tk.Tk()
root.title("Network-Related Question Chatbot")
root.geometry("600x450")
root.configure(width=470, height=550, bg=BG_COLOR)  # Background color

# Set a custom font and style
title_font = ("Helvetica", 16, "bold")
text_font = ("Helvetica", 12)



# Create a frame for the input box and label
input_frame = tk.Frame(root, bg=BG_COLOR)
input_frame.pack(pady=10)


# Create a label for instructions
instruction_label = tk.Label(input_frame, text="Ask a network-related question or type 'end' to exit:", bg=BG_COLOR, fg=TEXT_COLOR,pady=10)
instruction_label.grid(row=0, column=0, padx=5)

# Create a text input box for user input
input_box = tk.Text(input_frame, height=2, width=50, font=text_font, bg="#ffffff", fg="#333333", borderwidth=2, relief="solid")
input_box.grid(row=1, column=0, padx=5, pady=5)

# Create a button to submit the query
submit_button = tk.Button(root, text="Ask", command=on_submit, font=("Helvetica", 12), bg="#007BFF", fg="white", relief="flat", padx=10, pady=5)
submit_button.pack(pady=10)

# Create a scrollable text box to display the response
response_box = scrolledtext.ScrolledText(root, height=10, width=70, state=tk.DISABLED, wrap=tk.WORD, font=text_font, bg="#ffffff", fg="#333333", borderwidth=2, relief="solid")
response_box.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()

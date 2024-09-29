import nltk
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer

# Initialize the lemmatizer
lemmatizer = WordNetLemmatizer()

# Knowledge Base for Networking Problems
knowledge_base = {
    "malicious packets": {
        "solution": "To prevent malicious packets, ensure firewalls are configured correctly, and use packet sniffers like Wireshark to monitor traffic.",
        "detection": "Use IDS/IPS tools like Snort or Suricata to detect malicious packets in your network.",
    },
    "intrusion detection": {
        "solution": "To prevent intrusion, use IDS tools like Snort or Suricata and ensure network segmentation and encryption.",
        "detection": "Deploy Honeypots or advanced intrusion detection systems that monitor unusual behavior in your network.",
    },
    "ddos attack": {
        "solution": "To mitigate DDoS attacks, use a DDoS protection service such as Cloudflare, or employ rate-limiting techniques on your servers.",
        "detection": "Monitor for unusual traffic spikes using network monitoring tools and alert on abnormal traffic patterns.",
    },
    # Add more network-related issues and solutions as needed
}

# Function to preprocess user input
def preprocess(text):
    tokens = word_tokenize(text.lower())  # Tokenize the text
    lemmas = [lemmatizer.lemmatize(token) for token in tokens]  # Lemmatize tokens
    return lemmas

# Chatbot function to respond to user queries using NLTK
def chatbot(question):
    # Preprocess the question to extract keywords
    processed_question = preprocess(question)
    
    # Search for matching keywords in the knowledge base
    for keyword in knowledge_base.keys():
        if keyword in processed_question:
            response = f"Detected issue: {keyword}\nSolution: {knowledge_base[keyword]['solution']}\nDetection: {knowledge_base[keyword]['detection']}"
            return response
    
    # Default response if no keyword matches
    return "I'm sorry, I don't have an answer for that specific issue. Can you try asking about something else related to networking?"

# Main chat loop
def main():
    print("Chatbot: Hello! I am your network security assistant. How can I help you today?")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit", "bye"]:
            print("Chatbot: Goodbye! Stay safe.")
            break
        response = chatbot(user_input)
        print(f"Chatbot: {response}")

if __name__ == "__main__":
    main()

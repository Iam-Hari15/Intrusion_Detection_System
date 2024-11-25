from flask import Flask, render_template
from sniffer import start_sniffer, detected_alerts

app = Flask(__name__)

@app.route('/')
def index():
    # Pass the detected_alerts list to the template
    return render_template('index.html', packets=detected_alerts)

if __name__ == "__main__":
    # Start the sniffer in a separate thread
    import threading
    sniffer_thread = threading.Thread(target=start_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    app.run(debug=True)

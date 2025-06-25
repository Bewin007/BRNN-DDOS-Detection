import pyshark
import pandas as pd
import numpy as np
from datetime import datetime
import asyncio
import nest_asyncio
from keras.models import load_model
from sklearn.preprocessing import StandardScaler
import warnings
import os
warnings.filterwarnings('ignore')  # Suppress warnings for cleaner output
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import threading

# Apply nest_asyncio patch for Jupyter environments
nest_asyncio.apply()

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Load your pre-trained model and scaler
model = load_model('brnn_model.h5')
scalar = StandardScaler()

# Define the features in the exact same order as during training
features = ['frame.len', 'ip.hdr_len', 'ip.len', 'ip.flags.rb', 'ip.flags.df', 
            'ip.flags.mf', 'ip.frag_offset', 'ip.ttl', 'ip.proto', 'tcp.srcport', 
            'tcp.dstport', 'tcp.len', 'tcp.ack', 'tcp.flags.res', 'tcp.flags.ns', 
            'tcp.flags.cwr', 'tcp.flags.ecn', 'tcp.flags.urg', 'tcp.flags.ack', 
            'tcp.flags.push', 'tcp.flags.reset', 'tcp.flags.syn', 'tcp.flags.fin', 
            'tcp.window_size', 'tcp.time_delta']

def configure_tshark():
    try:
        # Set tshark path - adjust for your system
        pyshark.tshark.tshark.get_process_path = lambda *args: "/usr/bin/tshark"
        return True
    except Exception as e:
        print(f"Error configuring tshark: {e}")
        return False

def extract_packet_features(packet):
    """Extract required features from a network packet."""
    try:
        data = {
            'timestamp': datetime.now().isoformat(),
            'frame.len': int(packet.length),
            'ip.hdr_len': int(packet.ip.hdr_len) if hasattr(packet, 'ip') else 0,
            'ip.len': int(packet.ip.len) if hasattr(packet, 'ip') else 0,
            'ip.flags.rb': int(packet.ip.flags_rb) if hasattr(packet, 'ip') else 0,
            'ip.flags.df': int(packet.ip.flags_df) if hasattr(packet, 'ip') else 0,
            'ip.flags.mf': int(packet.ip.flags_mf) if hasattr(packet, 'ip') else 0,
            'ip.frag_offset': int(packet.ip.frag_offset) if hasattr(packet, 'ip') else 0,
            'ip.ttl': int(packet.ip.ttl) if hasattr(packet, 'ip') else 0,
            'ip.proto': int(packet.ip.proto) if hasattr(packet, 'ip') else 0,
            'tcp.srcport': int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
            'tcp.dstport': int(packet.tcp.dstport) if hasattr(packet, 'tcp') else 0,
            'tcp.len': int(packet.tcp.len) if hasattr(packet, 'tcp') else 0,
            'tcp.ack': int(packet.tcp.ack) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.res': int(packet.tcp.flags_res) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.ns': int(packet.tcp.flags_ns) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.cwr': int(packet.tcp.flags_cwr) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.ecn': int(packet.tcp.flags_ecn) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.urg': int(packet.tcp.flags_urg) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.ack': int(packet.tcp.flags_ack) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.push': int(packet.tcp.flags_push) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.reset': int(packet.tcp.flags_reset) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.syn': int(packet.tcp.flags_syn) if hasattr(packet, 'tcp') else 0,
            'tcp.flags.fin': int(packet.tcp.flags_fin) if hasattr(packet, 'tcp') else 0,
            'tcp.window_size': int(packet.tcp.window_size) if hasattr(packet, 'tcp') else 0,
            'tcp.time_delta': float(packet.tcp.time_delta) if hasattr(packet, 'tcp') else 0,
        }
        return data
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

class TrafficAnalyzer:
    def __init__(self, window_size=25):
        self.window_size = window_size
        self.packet_buffer = []
        self.scaler = StandardScaler()
        
    def add_packet(self, packet_features):
        """Add a packet to the buffer and analyze if we have enough packets"""
        self.packet_buffer.append(packet_features)
        
        # Keep only the last window_size packets
        if len(self.packet_buffer) > self.window_size:
            self.packet_buffer = self.packet_buffer[-self.window_size:]
            
        # If we have enough packets, analyze them
        if len(self.packet_buffer) == self.window_size:
            self.analyze_traffic()
    
    def analyze_traffic(self):
        """Analyze the current window of packets"""
        # Convert to DataFrame
        df_window = pd.DataFrame(self.packet_buffer)
        
        # Extract features in correct order
        X_window = df_window[features].values
        
        # Scale the features (you should fit the scaler on your training data first)
        X_scaled = scalar.transform(X_window)
        
        # Reshape for LSTM input (1 sample, window_size timesteps, n_features)
        X_reshaped = X_scaled.reshape(1, self.window_size, len(features))
        
        # Make prediction
        prediction = model.predict(X_reshaped)
        prediction_class = "ATTACK" if prediction[0][0] < 0.5 else "NORMAL"
        confidence = prediction[0][0] if prediction_class == "NORMAL" else 1 - prediction[0][0]
        
        # Print results with color coding
        if prediction_class == "ATTACK":
            print(f"\033[91mALERT: Potential attack detected! (Confidence: {confidence:.2%})\033[0m")
        else:
            print(f"\033[92mStatus: Normal traffic (Confidence: {confidence:.2%})\033[0m")

async def async_capture(interface, packet_count=None):
    """Asynchronous packet capture function"""
    analyzer = TrafficAnalyzer()
    cap = pyshark.LiveCapture(interface=interface)
    
    try:
        print("\033[94mStarting real-time network monitoring...\033[0m")
        print("\033[94mPress Ctrl+C to stop\033[0m")
        
        for i, packet in enumerate(cap.sniff_continuously()):
            if packet_count and i >= packet_count:
                break
                
            packet_features = extract_packet_features(packet)
            if packet_features:
                analyzer.add_packet(packet_features)
                
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        # Ensure proper cleanup of the capture object
        await cap.close_async()
        print("\033[93mCapture session closed.\033[0m")

def monitor_network(interface="wlp0s20f3", packet_count=None):
    """Main function to monitor network traffic"""
    if not configure_tshark():
        print("Failed to configure tshark. Exiting.")
        return
    
    try:
        # Run the async capture
        loop = asyncio.get_event_loop()
        loop.run_until_complete(async_capture(interface, packet_count))
    except Exception as e:
        print(f"Error during capture: {e}")

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor")
        self.monitor_thread = None
        self.stop_monitoring = threading.Event()

        # Interface selection
        ttk.Label(root, text="Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_entry = ttk.Entry(root)
        self.interface_entry.grid(row=0, column=1, padx=5, pady=5)
        self.interface_entry.insert(0, "wlp0s20f3")  # Default interface

        # Packet count
        ttk.Label(root, text="Packet Count (optional):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.packet_count_entry = ttk.Entry(root)
        self.packet_count_entry.grid(row=1, column=1, padx=5, pady=5)

        # Start button
        self.start_button = ttk.Button(root, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=2, column=0, padx=5, pady=10)

        # Stop button
        self.stop_button = ttk.Button(root, text="Stop Monitoring", command=self.stop_monitoring_gui, state="disabled")
        self.stop_button.grid(row=2, column=1, padx=5, pady=10)

        # Status label
        self.status_label = ttk.Label(root, text="Status: Idle", foreground="blue")
        self.status_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def start_monitoring(self):
        interface = self.interface_entry.get()
        packet_count = self.packet_count_entry.get()
        packet_count = int(packet_count) if packet_count.isdigit() else None

        self.stop_monitoring.clear()
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.status_label.config(text="Status: Monitoring...", foreground="green")

        # Run monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.run_monitoring, args=(interface, packet_count))
        self.monitor_thread.start()

    def stop_monitoring_gui(self):
        self.stop_monitoring.set()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Status: Stopped", foreground="red")

    def run_monitoring(self, interface, packet_count):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.async_monitor(interface, packet_count))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            self.stop_monitoring_gui()

    async def async_monitor(self, interface, packet_count):
        analyzer = TrafficAnalyzer()
        cap = pyshark.LiveCapture(interface=interface)

        try:
            for i, packet in enumerate(cap.sniff_continuously()):
                if self.stop_monitoring.is_set():
                    break
                if packet_count and i >= packet_count:
                    break

                packet_features = extract_packet_features(packet)
                if packet_features:
                    analyzer.add_packet(packet_features)
        except KeyboardInterrupt:
            pass
        finally:
            await cap.close_async()

if __name__ == "__main__":
    # IMPORTANT: Fit the scaler on your training data before using this
    # For demonstration, we'll create a dummy scaler - replace with your actual scaler
    dummy_data = np.random.rand(100, len(features))
    scalar.fit(dummy_data)
    
    # Start GUI
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()
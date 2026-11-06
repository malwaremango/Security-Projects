# -*- coding: utf-8 -*-
"""
Created on Thu Sep 17 12:10:04 2026

@author: usah5
"""
#run this script to display the monitoring dashboad (dashboard.py) on a web browser 
import time
import random
from threading import Thread, Lock
from flask import Flask, jsonify
from dashboard import get_dashboard

import os # Forhindrer at Flask starter simulatoren dobbelt
app = Flask(__name__)


# Thread lock --------------------------------------------------


data_lock = Lock()


# Solar park state --------------------------------------------------


solar_park_data = {
    "status": "NORMAL",
    "temperature": 23.9,
    "power_mw": 4.26,

    "pv_panels": {
        "status": "ONLINE",
        "temperature": 23.9
    },

    "inverter": {
        "status": "ONLINE",
        "output_mw": 4.26
    },

    "plc": {
        "status": "ONLINE",
        "value": 0
    },

    "scada": {
        "status": "ONLINE"
    },

    "network": {
        "status": "NORMAL"
    },

    "alerts": []
}



# Add security alert function


def add_alert(level, message):
    """
    Legger til et sikkerhetsvarsel øverst i dashboardet.
    """

    timestamp = time.strftime("%H:%M:%S")

    solar_park_data["alerts"].insert(0, {
        "timestamp": timestamp,
        "level": level,
        "message": message
    })



# Solar park simulator --------------------------------------------------

def run_simulator():

    tick = 0    # Counter starts at 0.  Tick 1 equals one second! 

    while True:

        time.sleep(2)

        with data_lock:

            tick += 1


         
            # 1. NORMAL SENSOR DATA
           

            temperature = round(
                22 + random.uniform(0, 6),
                1
            )

            solar_park_data["temperature"] = temperature
            solar_park_data["pv_panels"]["temperature"] = temperature


            # --------------------------------------------------
            # 2. POWER GENERATION
            # --------------------------------------------------

            if solar_park_data["status"] == "NORMAL":

                power = round(
                    random.uniform(4.0, 5.2),
                    2
                )

                solar_park_data["power_mw"] = power
                solar_park_data["inverter"]["output_mw"] = power

            else:

                solar_park_data["power_mw"] = 0.0
                solar_park_data["inverter"]["output_mw"] = 0.0


            # ==================================================
            # RECONNAISSANCE
            

            
            # NMAP SCAN
            

            if tick == 2:

                add_alert(
                    "ALERT",
                    "NMAP OS detection scan detected from external IP "
                    "192.168.10.55 targeting SCADA-01."
                )


            # --------------------------------------------------
            # MODBUS SCANNING
            # --------------------------------------------------

            if tick == 3:

                add_alert(
                    "ALERT",
                    "Modbus TCP port scanning (port 502) detected "
                    "on subnet 192.168.10.0/24."
                )


            # ==================================================
            # BRUTE FORCE / INITIAL ACCESS
            # ==================================================

            # --------------------------------------------------
            # FAILED LOGINS
            # --------------------------------------------------

            if tick == 5:

                add_alert(
                    "ALERT",
                    "Multiple failed login attempts from "
                    "192.168.10.55. Possible brute-force attack."
                )


            # --------------------------------------------------
            # SUCCESSFUL LOGIN
            # --------------------------------------------------

            if tick == 6:

                add_alert(
                    "CRITICAL",
                    "Unauthorized SSH login successful on SCADA gateway "
                    "from 192.168.10.55. Session established."
                )


            # ==================================================
            # PRE-COMPROMISE
            # ==================================================

            if tick == 8:

                add_alert(
                    "ALERT",
                    "Suspicious authentication activity detected "
                    "between SCADA gateway and engineering workstation."
                    
                )


            # --------------------------------------------------
            # INVERTER HEARTBEAT
            # --------------------------------------------------

            if tick == 9:

                add_alert(
                    "CRITICAL",
                    "Inverter-01 heartbeat timeout. Disconnected "
                    "from SCADA master server."
                )


            # ==================================================
            # SYSTEM COMPROMISED
            # ==================================================

            if tick == 10:

                solar_park_data["status"] = "COMPROMISED"
                solar_park_data["network"]["status"] = "SUSPICIOUS"

                solar_park_data["plc"]["value"] = 999

                solar_park_data["inverter"]["status"] = "OFFLINE"
                solar_park_data["inverter"]["output_mw"] = 0.0

                solar_park_data["power_mw"] = 0.0

                add_alert(
                    "CRITICAL",
                    "Unexpected Modbus write command detected. "
                    "PLC 192.168.10.20, register 40001 changed "
                    "from 0 to 999. Unauthorized control suspected."
                )


            # ==================================================
            # POST-COMPROMISE
            # ==================================================

            # --------------------------------------------------
            # PRIVILEGE ESCALATION
            # --------------------------------------------------

            if tick == 11:

                add_alert(
                    "CRITICAL",
                    "Privilege escalation detected on SCADA-01. "
                    "Unauthorized account obtained administrative privileges."
                )


            # --------------------------------------------------
            # SCADA CONFIGURATION CHANGE
            # --------------------------------------------------

            if tick == 12:

                add_alert(
                    "CRITICAL",
                    "Unauthorized SCADA configuration change detected. "
                    "Alarm thresholds modified on SCADA-01."
                )


            # ==================================================
            # MALWARE ATTACK
            # ==================================================

            
            # MALWARE DETECTED
            

            if tick == 13:

                solar_park_data["scada"]["status"] = "INFECTED"

                add_alert(
                    "CRITICAL",
                    "Malware detected on SCADA-01. "
                    "Suspicious executable activity detected "
                    "on the SCADA server."
                )


            # --------------------------------------------------
            # LATERAL MOVEMENT
            # --------------------------------------------------

            if tick == 14:

                add_alert(
                    "CRITICAL",
                    "Malware attempting lateral movement from SCADA-01 "
                    "toward PLC and engineering workstation."
                )


            
            # TELEMETRY MANIPULATION
            

            if tick == 15:

                solar_park_data["temperature"] = 91.4
                solar_park_data["pv_panels"]["temperature"] = 91.4

                add_alert(
                    "CRITICAL",
                    "Malware-induced telemetry manipulation detected. "
                    "SCADA sensor values inconsistent with field measurements."
                    "Solar Panels Too Hot"
                )


            # --------------------------------------------------
            # MALICIOUS MODBUS ACTIVITY
            # --------------------------------------------------

            if tick == 16:

                solar_park_data["plc"]["value"] = 777

                add_alert(
                    "CRITICAL",
                    "Unauthorized Modbus write operation detected. "
                    "Multiple PLC registers modified from SCADA network."
                )


            
            # MALWARE AFFECTS INVERTER
            

            if tick == 17:

                solar_park_data["inverter"]["status"] = "DEGRADED"
                solar_park_data["inverter"]["output_mw"] = 0.8
                solar_park_data["power_mw"] = 0.8

                add_alert(
                    "CRITICAL",
                    "Malware activity affecting inverter control process. "
                    "Solar production output reduced from 4.26 MW to 0.80 MW."
                )


            
            # SECURITY MONITORING ATTACK
            

            if tick == 18:

                add_alert(
                    "CRITICAL",
                    "Attempt to disable SCADA security monitoring detected. "
                    "Endpoint protection service termination blocked."
                )


            
            # COMMAND AND CONTROL
            

            if tick == 19:

                solar_park_data["network"]["status"] = "SUSPICIOUS"

                add_alert(
                    "CRITICAL",
                    "Command-and-control communication detected "
                    "from SCADA-01 to unknown external host."
                )


            
            # ADDITIONAL IMPACT
            

            
            # DATA EXFILTRATION
            
            if tick == 20:

                add_alert(
                    "CRITICAL",
                    "Data exfiltration alert: High-volume outbound "
                    "traffic detected from SCADA-01 to unknown "
                    "external network."
                )


            
            # DENIAL OF SERVICE
            

            if tick == 21:

                solar_park_data["scada"]["status"] = "DEGRADED"

                add_alert(
                    "CRITICAL",
                    "Possible denial-of-service attack detected. "
                    "SCADA polling requests significantly increased."
                )


            
            # INCIDENT RESPONSE
           

            
            # FIREWALL ISOLATION
            

            if tick == 22:

                solar_park_data["network"]["status"] = "ISOLATED"

                add_alert(
                    "ALERT",
                    "Incident Response team initiated firewall "
                    "isolation protocol. Attacker IP blocked."
                )


     
            # NETWORK ISOLATION
         

            if tick == 23:

                add_alert(
                    "ALERT",
                    "SCADA network isolated from external WAN. "
                    "Remote access temporarily disabled."
                )



            # MALWARE REMOVAL
            

            if tick == 24:

                solar_park_data["scada"]["status"] = "RECOVERING"

                add_alert(
                    "NORMAL",
                    "Malware removed from SCADA-01. "
                    "System integrity verification and forensic "
                    "analysis initiated."
                )


          
            # SYSTEM RECOVERY
          

            if tick == 25:

                solar_park_data["status"] = "NORMAL"

                solar_park_data["network"]["status"] = "NORMAL"

                solar_park_data["scada"]["status"] = "ONLINE"

                solar_park_data["plc"]["status"] = "ONLINE"
                solar_park_data["plc"]["value"] = 0

                solar_park_data["inverter"]["status"] = "ONLINE"

                solar_park_data["inverter"]["output_mw"] = 4.26

                solar_park_data["power_mw"] = 4.26

                solar_park_data["temperature"] = 23.9
                solar_park_data["pv_panels"]["temperature"] = 23.9

                add_alert(
                    "NORMAL",
                    "Malware incident resolved. SCADA services restored, "
                    "PLC registers reset, system integrity verified "
                    "and solar production resumed."
                )



# Flask API


@app.route('/data')
def get_data():

    """
    Sender oppdaterte telemetridata til HTML-dashboardet.
    """

    with data_lock:
        return jsonify(solar_park_data)



# Dashboard


@app.route('/')
def index():

    """
    Henter HTML-koden fra dashboard.py.
    """

    return get_dashboard()



# Start application


if __name__ == '__main__':



    if not os.environ.get("WERKZEUG_RUN_MAIN"):

        Thread(
            target=run_simulator,
            daemon=True
        ).start()

    # Starter Flask-server Serveren kjører på localhost og port 5000
    app.run(
        debug=True,
        port=5000,
        use_reloader=False
    )

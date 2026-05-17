# LAYER 1: The Foundation. 
# Instead of a heavy Ubuntu server, we start with a stripped-down, 
# lightweight Linux image that already has Python 3 pre-installed.
FROM python:3.10-slim

# LAYER 2: The Workspace.
# This creates a folder inside the container and moves us into it.
WORKDIR /opt/soc-defender

# LAYER 3: Dependencies.
# Our script calls 'sudo ufw' to ban attackers. The slim Python image 
# doesn't have these network tools, so we install them.
RUN apt-get update && apt-get install -y sudo ufw iptables

# LAYER 4: The Payload.
# This copies your heavily engineered log_parser.py script from 
# your Ubuntu server (the first dot) into the container (the second dot).
COPY log_parser.py .

# LAYER 5: The Ignition.
# This tells the container what to execute the millisecond it boots up. 
# (The '-u' flag forces Python to output logs in real-time without buffering).
CMD ["python3", "-u", "log_parser.py"]

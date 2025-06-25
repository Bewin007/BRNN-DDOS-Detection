# Use a lightweight Python base image
FROM python:3.7.17-slim-bookworm

# Set environment variable to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install dependencies
RUN apt-get update && apt-get install -y \
    sudo \
    curl \
    npm \
    nodejs \
    git \
    tcpdump \
    tshark \
    iproute2 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create Jupyter user before modifying groups
RUN useradd -m -s /bin/bash jupyteruser

# Allow non-root users to run TShark without sudo
RUN groupadd -r wireshark && usermod -aG wireshark jupyteruser && \
    chmod +x /usr/bin/dumpcap && setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Install Python packages, including PyShark
# RUN pip install --no-cache-dir \
#     jupyterlab \
#     notebook \
#     pyshark
# Install configurable-http-proxy globally using npm
RUN npm install -g configurable-http-proxy

# Install Python packages, including PyShark and JupyterHub
RUN pip install --no-cache-dir \
    jupyterhub \
    notebook \
    jupyterlab \
    pyshark


# Set the working directory
WORKDIR /home/jupyteruser/notebooks

# Change ownership to the Jupyter user
RUN chown -R jupyteruser:jupyteruser /home/jupyteruser

# Expose JupyterHub port
EXPOSE 8000
EXPOSE 8001

# Set default command to run JupyterHub
CMD ["jupyterhub", "--no-ssl"]

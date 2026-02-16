FROM zeek/zeek:latest

WORKDIR /srv

# Install apt packages from list
COPY apt-packages.txt /srv/apt-packages.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
    $(tr '\n' ' ' < /srv/apt-packages.txt) \
  && rm -rf /var/lib/apt/lists/*

# Create venv and install python deps into it (avoids PEP 668 system pip restrictions)
ENV VENV_PATH=/opt/venv
RUN python3 -m venv ${VENV_PATH}
ENV PATH="${VENV_PATH}/bin:${PATH}"

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

# App
COPY app /srv/app

ENV PYTHONUNBUFFERED=1

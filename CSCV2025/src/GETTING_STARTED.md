# Getting Started

## Interacting with the Server

The `client.py` file provides an example of how to interact with the remote server.

## Setting Up a Local Server

To start a local server for testing, run the following command:

```sh
socat -T 20 -d -d TCP-LISTEN:1337,reuseaddr,fork EXEC:"python -u main.py"
```

Once the server is running, you can interact with the local instance. For example, using `client.py`:

```sh
python client.py
```
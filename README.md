# websocket
Small python library for using websockets.

## Usage

```python
import websocket

# Create socket
# See http://www.websocket.org/echo.html for this connection.
c = websocket.WebSocket('ws://echo.websocket.org/')

# Open connection (and do handshake)
c.connect()

# Send a message
c.send("Rock it with HTML5 WebSocket")

# Receive a message
print(c.receive().message())

# Close the connection
c.close()
```

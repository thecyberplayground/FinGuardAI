import socketio

sio = socketio.Client()

@sio.event
def connect():
    print('Connected to backend')
    # Replace with a real IP/host you want to test
    sio.emit('start_passive_monitoring', {'host': '192.168.43.20'})

@sio.event
def disconnect():
    print('Disconnected from backend')

@sio.on('passive_stats_update')
def on_stats_update(data):
    print('Received passive_stats_update:', data)

@sio.on('passive_monitoring_error')
def on_error(data):

    print('Received passive_monitoring_error:', data)

if __name__ == '__main__':
    sio.connect('http://127.0.0.1:5001')
    sio.wait()

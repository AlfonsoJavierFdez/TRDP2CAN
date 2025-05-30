import can
import time

bus = can.interface.Bus(channel='can0', interface='socketcan')

message = can.Message(arbitration_id=0x123, data =[0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88], is_extended_id=False)


try:
    while True:
        bus.send(message)
        print("Mensaje enviado: {}".format(message))
        time.sleep(0.01) 
except can.CanError:
    print("Error al enviar el mensaje")
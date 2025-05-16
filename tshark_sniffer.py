import os
import subprocess
from datetime import datetime


def change_ip(new_ip,netmask):
    # Change the IP to be in the same subnet as the monitored devices
    #new_ip = input("Introduce la nueva dirección IP: ")
    os.system(f'sudo ifconfig eth0 {new_ip} netmask {netmask} up')
    
def set_Netfilter(port_list,src_ip_list,dst_ip_list):
    #tshark filter
    if port_list:
        ports_filter = 'or '.join([f'port {port} ' for port in port_list])
    if src_ip_list:
        src_ip_filter = 'or '.join([f'host {src_ip} ' for src_ip in src_ip_list])
    if dst_ip_list:
        dst_ip_filter = 'or '.join([f'host {dst_ip} ' for dst_ip in dst_ip_list])
        
    complete_filter = f'udp and ({ports_filter}) and ({src_ip_filter}) and ({dst_ip_filter})'
    print(complete_filter)
    return complete_filter

def capture_packets():
    
    date_hour = datetime.now().strftime("%d%m%Y_%H%M%S")
    OutFile = f'capture_{date_hour}.pcap'
    Netfilter = set_Netfilter(ports,src_ips,dst_ips)
    # tcpdump command to sniff UDP packets the specified port
    command = [
        'tshark',
        '-i', 'eth0',       # interfaz red a analizar (eth0)
        '-f', f'{Netfilter}',
        '-w', f'{OutFile}',      # Guardar en un archivo pcap
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.dstport',
        #'-e', 'frame.len',
        '-e', 'data'
    ]
   
    print(f'Capturando paquetes UDP...(Ctrl+C para detener y guardar la captura)')
    
    try:
        # Ejecutar tshark y capturar salida
        process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        
        while True:
            
            output = process.stdout.readline() 
            if not output:
                print('Sin entrada (Puede que tu filtro sea demasiado restrictivo o esté mal configurado)')
                break
            
            packetdata = output.decode('utf-8').strip()
            if packetdata:
                #print(f'Packet received: {packetdata}')
                fields = packetdata.split('\t')
                #print(f'Packet splited: {fields}')
                if len(fields) >= 3:
                    src_ip = fields[0]
                    dst_ip = fields[1]
                    dst_port = fields[2]
                    #data_len = fields[3] # incluye header (solo nos importa el tamaño del payload)
                    data_hex = fields[3] if len(fields) > 3 else ''
                    
                    # Convertir contenido a bytes
                    data_bytes = bytes.fromhex(data_hex.replace(':',''))
                    data_list = list(data_bytes)
                    data_len = len(data_list)
                    #print(f"Paquete capturado en puerto {dst_port} con IP de origen: {src_ip}, IP de destino: {dst_ip} y tamaño {data_len} bytes")
                    #print(f"Contenido: {data_list}")
                    #print('-' * 40)
                    
    except KeyboardInterrupt:
        
        print("Captura detenida. Guardando datos...")
        process.terminate()
        print(f"Datos guardados en {OutFile}")
        
    except Exception as e:
        print(f"Ocurrió un error: {e}")
        process.terminate()
     
        
if __name__ == "__main__":
    
    #port = input("Introduce el puerto a capturar: ")
    #src_ip_filter = input("Introduce la dirección IP de origen a filtrar (dejar en blanco para no filtrar): ")
    new_ip = "192.168.1.100"
    netmask = "255.255.255.0"
    change_ip(new_ip,netmask)
    
    ports = [5007, 8888]
    src_ips=["192.168.1.251"]
    dst_ips=['224.1.1.1','224.1.3.3']
    
    capture_packets()
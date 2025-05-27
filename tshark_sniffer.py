import os
import subprocess
import json
import csv
from datetime import datetime

def Config_load(UDPconfig_file):
    with open(UDPconfig_file,'r') as f:
        return json.load(f)
    
def change_ip():
    # Change the IP to be in the same subnet as the monitored devices
    #new_ip = input("Introduce la nueva direcciÃ³n IP: ")
    if UDPconfig.get('Device',{}).get('New_config',True):
        new_ip = UDPconfig.get('Device',{}).get('IP_Address')
        netmask = UDPconfig.get('Device',{}).get('Netmask')
        os.system(f'sudo ifconfig eth0 {new_ip} netmask {netmask} up')
    
def set_Netfilter():
    
    #tshark filter
    complete_filter = 'udp'
    if UDPconfig.get('ports',{}).get('enable',True):
        port_list = UDPconfig.get('ports',{}).get('Whitelist',[])
        ports_filter = 'or '.join([f'port {port} ' for port in port_list])
        complete_filter += f' and ({ports_filter})'
        
    if UDPconfig.get('src_ips',{}).get('enable',True):
        src_ip_list = UDPconfig.get('src_ips',{}).get('Whitelist',[])
        src_ip_filter = 'or '.join([f'src host {src_ip} ' for src_ip in src_ip_list])
        complete_filter += f' and ({src_ip_filter})'
        
    if UDPconfig.get('dst_ips',{}).get('enable',True):
        dst_ip_list = UDPconfig.get('dst_ips',{}).get('Whitelist',[])
        dst_ip_filter = 'or '.join([f'dst host {dst_ip} ' for dst_ip in dst_ip_list])
        complete_filter += f' and ({dst_ip_filter})'
    
    #complete_filter = f'udp and ({ports_filter}) and ({src_ip_filter}) and ({dst_ip_filter})'
    print(complete_filter)
    return complete_filter

def capture_packets():
    
    date_hour = datetime.now().strftime("%d%m%Y_%H%M%S")
    pcapFile = f'capture_{date_hour}.pcap'
    csvFile = f'data_{date_hour}.csv'
    
    Netfilter = set_Netfilter()
    # tcpdump command to sniff UDP packets the specified port
    command = [
        'tshark',
        '-i', 'eth0',       # interfaz red a analizar (eth0)
        '-f', f'{Netfilter}',
        '-w', f'{pcapFile}',      # Guardar en un archivo pcap
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.dstport',
        '-e', 'frame.time_epoch',
        '-e', 'data'
    ]
    
    csvfile = open(csvFile, mode='w', newline = '')
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['Timestamp', 'SeqCnt', 'COMID','RawFilterData','VarSizes','Variables']) # Encabezados csv
    first_timestamp = None
    
    Filterconfig = Config_load('msgFilter.json')
    Header_size = Filterconfig['config']['Header_size']
    COM_ID_index = Filterconfig['config']['COM_ID_index']
    COM_ID_size = Filterconfig['config']['COM_ID_size']
    SeqCnt_index = Filterconfig['config']['SeqCnt_index']
    SeqCnt_size = Filterconfig['config']['SeqCnt_size']
    endian = Filterconfig['config']['endian']
    msgFilter = Filterconfig['msgFilter']
    
    comIDs_whitelist = {msg['COM_ID']:msg['signals'] for msg in msgFilter} # conjunto de COM_IDs permitidos
    
    # Eliminar COM_ID 0 de los COM:IDs permitidos
    if 0 in comIDs_whitelist:
        del comIDs_whitelist[0]
        
    print(f'Capturando paquetes UDP...(Ctrl+C para detener y guardar la captura)')
    
    try:
        # Ejecutar tshark y capturar salida
        process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        
        while True:
            
            output = process.stdout.readline() 
            if not output:
                print('Sin entrada (Puede que tu filtro sea demasiado restrictivo o estÃ© mal configurado)')
                break
            
            packetdata = output.decode('utf-8').strip()
            if packetdata:
                #print(f'Packet received: {packetdata}')
                fields = packetdata.split('\t')
                #print(f'Packet splited: {fields}')
                if len(fields) >= 4:
                    src_ip = fields[0]
                    dst_ip = fields[1]
                    dst_port = fields[2]
                    timestamp = float(fields[3]) 
                    data_hex = fields[4] if len(fields) > 4 else ''
                    
                    # Convertir contenido a bytes
                    data_bytes = bytes.fromhex(data_hex.replace(':',''))
                    data_list = list(data_bytes)
                    data_len = len(data_list)
                    
                    if first_timestamp is None:
                        first_timestamp = timestamp
                    
                    #print(f"Paquete capturado en puerto {dst_port} con IP de origen: {src_ip}, IP de destino: {dst_ip} y tamaÃ±o {data_len} bytes")
                    #print(f"Contenido: {data_list}")
                    #print('-' * 40)
                    COMID = int.from_bytes(data_list[COM_ID_index:COM_ID_index+(COM_ID_size)],byteorder=endian)  # 'big' para big-endian y 'little' para little-endian
                    #print(f'COMID: {COMID}')
                    SeqCnt = int.from_bytes(data_list[SeqCnt_index:SeqCnt_index+(SeqCnt_size)],byteorder=endian)
                    
                    if COMID in comIDs_whitelist:
                        print(f'COMID {COMID} in whitelist')
                        timestamp_fix = timestamp - first_timestamp
                        RawFilterData = []
                        VarSizes = []
                        Variables = []
                        signals = comIDs_whitelist[COMID]
                        
                        for signal in signals:
                            byte_index = signal['byte_index']
                            #print(f'byte_index:{byte_index}')
                            byte_index += Header_size
                            #print(f'byte_index+Header:{byte_index}')
                            size = signal['size']
                            #print(f'size:{size}')
                            if size>0:
                                if byte_index + size <= len(data_list):
                                    signal_bytes = data_list[byte_index:byte_index + size]
                                    RawFilterData.extend(signal_bytes)
                                    #print(f'RawFilterData:{RawFilterData}')
                                    
                                    if size == 1 or size == 2 or size == 4 or size == 8:
                                        # Almacenar el tamaÃ±o de la variable
                                        VarSizes.append(size)
                                        # Convertir bytes a variable del tamaÃ±o determinado
                                        signal_value = int.from_bytes(signal_bytes, byteorder =endian, signed=False)
                                        # Almacenar el valor entero de la lista
                                        Variables.append(signal_value)
                                    else:
                                        print(f'TamaÃ±o de variable no soportado: {size}')
                                       
                                        
                                else:
                                    print(f'byte_index out of reach (Header size + byte_index = {byte_index} > Data length = {len(data_list)})')
                        
                        # Convertir lista de enteros en cadena separada por comas
                        VarSizes_str =  ','.join(map(str,VarSizes))
                        Variables_str = ','.join(map(str,Variables))
                        # Escribir en el archivo CSV
                        csv_writer.writerow([timestamp_fix,SeqCnt,COMID,RawFilterData,VarSizes_str,Variables_str])
                    else:
                        #print(f'Rejected COMID: {COMID}')
                        continue #omite el resto del bucle

                    
                    
    except KeyboardInterrupt:
        
        print("Captura detenida.Guardando datos...")
        process.terminate()
        print(f"Datos guardados en {pcapFile}")
        
    except Exception as e:
        print(f"OcurriÃ³ un error: {e}")
        process.terminate()
    
    finally:
        csvfile.close()
     
        
if __name__ == "__main__":
    
    UDPconfig = Config_load('UDPconfig.json')

    change_ip()
    
    capture_packets()

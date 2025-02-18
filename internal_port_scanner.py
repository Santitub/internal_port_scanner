from logging import getLogger, ERROR, basicConfig, DEBUG
from colorama.ansi import clear_screen, AnsiCursor
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Back, init
from multiprocessing import cpu_count, Pool
from argparse import ArgumentParser
from socket import getservbyport
from scapy.sendrecv import sr1, conf, sr
from sys import exit, argv
from scapy.volatile import RandShort
from scapy.layers.inet import IP, TCP
from tqdm import tqdm
from time import time

# Configuración de logging
getLogger("scapy.runtime").setLevel(ERROR)  # Desactiva los warnings
basicConfig(level=DEBUG, format='%(threadName)s: %(message)s')

# Configuración de scapy
conf.verb = 0  # Desactiva la salida de scapy

# Obtener el timeout dinámicamente (basado en la latencia o condiciones de red)
def get_dynamic_timeout():
    return 1  # Ajusta este valor en función de la latencia de la red

# Función para escanear puertos de una dirección
def scann_ports(args):
    try:
        addr, range_, process_id, thread_is = args
        min_p, max_p = range_  # Puertos a escanear
        open_ports = []

        for puerto in tqdm(range(min_p, max_p), desc=f"\r{AnsiCursor.FORWARD(process_id)}{Fore.LIGHTYELLOW_EX}Proceso {Fore.LIGHTCYAN_EX}{process_id} thread {Fore.LIGHTCYAN_EX}{process_id}{Fore.RESET}", position=process_id + 1, leave=False):
            puertoOrigen = RandShort()
            paquete = IP(dst=addr) / TCP(sport=puertoOrigen, dport=puerto, flags="S")
            try:
                respuesta = sr1(paquete, timeout=get_dynamic_timeout())
                if respuesta and respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12:
                    p = IP(dst=addr) / TCP(sport=puertoOrigen, dport=puerto, flags="R")
                    sr(p, timeout=1)
                    try:
                        servicio = getservbyport(puerto)
                    except:
                        servicio = "¿?"
                    open_ports.append((puerto, servicio))
            except Exception as e:
                print(f"Error en el puerto {puerto}: {e}")
        return open_ports
    except KeyboardInterrupt:
        pass
    print("\n\n")
    return []

# Función para dividir el escaneo entre hilos
def scann_ports_thread(args):
    addr, range_, process_id, threads = args
    open_ports = []
    args_list = []
    k, j = range_

    for i in range(threads):
        j = k  # Valor mínimo
        k += (range_[1] - range_[0]) // threads  # Dividir los puertos a escanear en la cantidad especificada
        if i == threads - 1:  # El último hilo se encargará de los puertos sobrantes
            k += (range_[1] - range_[0]) % threads
        args_list.append((addr, (j, k), process_id, i))
        print(f"\r{Fore.LIGHTYELLOW_EX}process id {Fore.LIGHTCYAN_EX}{process_id} thread id {Fore.LIGHTCYAN_EX}{i} {Fore.LIGHTYELLOW_EX}>>> {Fore.LIGHTCYAN_EX}{addr}{Fore.LIGHTYELLOW_EX}:{Fore.LIGHTCYAN_EX}{(j, k)}{Fore.RESET}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for i in args_list:
            open_ports.extend(executor.submit(scann_ports, i).result())
    return open_ports

# Función principal
if __name__ == '__main__':
    init()

    # Configuración de los argumentos de la línea de comandos
    parser = ArgumentParser(prog=__doc__, description="Escaner de puertos multiproceso")
    parser.add_argument("-a", "--addr", help="Dirección a la que realizar el escaneo", type=str)
    parser.add_argument("-p", "--ports", help="Puertos a escanear, por defecto todos. Se puede especificar un rango usando un guion: 10-24", type=str, default="1-65535")
    parser.add_argument("-up", "--utilization-percentage", help="Porcentaje de cores a usar. Por defecto 80%", type=int, default=80)
    parser.add_argument("-t", "--thread-cores", help="Cantidad de hilos a usar por proceso, por defecto 4", type=int, default=4)

    # Verificar si se pasaron argumentos
    if len(argv) <= 1:
        parser.print_help()
        exit(1)

    parser = parser.parse_args()
    
    # Verificar que la dirección de escaneo sea válida
    if not parser.addr:
        print(f"{Fore.LIGHTRED_EX}Error: Debes proporcionar una dirección con --addr")
        exit(1)

    listaPuertos = parser.ports

    # Validación del rango de puertos
    if '-' in listaPuertos:
        try:
            listaPuertos = tuple(map(int, listaPuertos.split("-")))
        except ValueError:
            print(f"{Fore.LIGHTRED_EX}--ports{Fore.RESET} no tiene un rango válido definido")
            exit(1)
    else:
        listaPuertos = (1, 65535)  # Si no se pasa un rango válido, usar el rango completo

    # Calcular la cantidad de procesos y hilos a usar
    cores = int(cpu_count() * parser.utilization_percentage / 100)
    print(f"Puertos a escanear: {listaPuertos}")
    print(f"\n{Fore.LIGHTYELLOW_EX}Número de procesos a usar: {cores}{Fore.RESET}")
    print(f"\n{Fore.LIGHTYELLOW_EX}Número de hilos por proceso a usar: {parser.thread_cores}{Fore.RESET}")
    print(f"\n{Fore.LIGHTYELLOW_EX}Puertos a escanear por proceso: {(listaPuertos[1] - listaPuertos[0]) // cores}{Fore.RESET}")

    # Dividir los puertos entre los procesos
    args_list = []
    j, k = (listaPuertos[0], listaPuertos[0])
    for i in range(cores):
        j = k  # Valor mínimo
        k += (listaPuertos[1] - listaPuertos[0]) // cores  # Dividir los puertos a escanear
        if i == cores - 1:  # El último proceso tomará los puertos sobrantes
            k += (listaPuertos[1] - listaPuertos[0]) % cores
        args_list.append((parser.addr, (j, k), i, parser.thread_cores))
        print(f"{Fore.LIGHTYELLOW_EX}process id {Fore.LIGHTCYAN_EX}{i} {Fore.LIGHTYELLOW_EX}>>> {Fore.LIGHTCYAN_EX}{parser.addr}{Fore.LIGHTYELLOW_EX}:{Fore.LIGHTCYAN_EX}{(j, k)}{Fore.RESET}")

    # Ejecutar los procesos
    with Pool(processes=cores) as pool:
        try:
            results = list(pool.imap(scann_ports_thread, args_list))
        except KeyboardInterrupt:
            pass

    # Mostrar los resultados
    print(clear_screen())
    for result in results:
        for data in result:
            for port, service in data:
                print(f"\r{Fore.LIGHTMAGENTA_EX}[{Fore.LIGHTGREEN_EX}{Back.LIGHTBLUE_EX}ABIERTO{Back.RESET}{Fore.LIGHTMAGENTA_EX}]{Fore.LIGHTYELLOW_EX} {port} {Fore.LIGHTGREEN_EX}/{Fore.LIGHTYELLOW_EX}tcp {Fore.LIGHTGREEN_EX}->{Fore.LIGHTGREEN_EX} {service} {Fore.RESET}")
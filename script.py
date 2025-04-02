import dns.resolver
import re
import json 
from termcolor import colored
from prettytable import PrettyTable
import inquirer
import os
import sys
import tty
import termios

tableauAllDatas = [] 
assets = []
def get_txt_records(domain):
    try:
        datas = []
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            datas.append(record.to_text().replace("\"",""))
        return datas
    except Exception as e:
        print(e)
        return False
def checkVulnDmarc(domain):
    ###############################
    # Récuperation des champs TXT #
    ###############################

    try:
        table = PrettyTable()
        table.field_names  = ["Misconfig element","Description"]
        txt_records = dns.resolver.resolve(domain, 'TXT')
        
        for record in txt_records:
            record_text = record.to_text()
            if "spf" in record_text.lower() or "dmarc" in record_text.lower():
                
                rua_match = re.search(r'rua=mailto:([^,;]+)', record_text)
                ruf_match = re.search(r'ruf=mailto:([^,;]+)', record_text)
                
                if rua_match:
                    rua_email = rua_match.group(1)
                    if not rua_email.endswith(f"@{domain}"):
                        table.add_row(["RUA","RUA mal configuré ({ruf_email}). Ne correspond pas au domaine {domain}."])
                if ruf_match:
                    ruf_email = ruf_match.group(1)
                    if not ruf_email.endswith(f"@{domain}"):
                        table.add_row(["RUF","RUF mal configuré ({ruf_email}). Ne correspond pas au domaine {domain}."])
                if " p=none" in record_text:
                        table.add_row(["p","Le dmarc contient une politique 'p=none'."])
                pct_match = re.search(r"pct=(\d+)", record_text)
                if pct_match:
                    pct_value = int(pct_match.group(1))
                    if pct_value < 50:
                        pct_below_50 = True
                        table.add_row(["pct","Le paramètre pct est inferieur a 50."])
                if "sp=none" in record_text:
                    table.add_row(["sp","Le parametre sp est vulnérable (sp= none)"])
                if "rua="not in record_text:
                    table.add_row(["RUA","Absence de RUA dans le DMARC."])
                if "ruf=" not in record_text:
                    table.add_row(["RUF","Absence de RUF dans le DMARC."])
                if "?all" in record_text: 
                    table.add_row(["all","L'appelation ?all est présente dans le dmarc et n'est pas sécu !"])
                if len(record_text) > 255:
                    table.add_row(["general","La longueur de l'enregistrement dmarc est trop longue"])
                if "+all" in record_text:
                    table.add_row(["all","L'appelation +all est présente dans le dmarc et n'est pas sécu."])
        print("-----------")
        print(domain)
        print("-----------")
        print(table)            
    except Exception as e:
        print(e)
        #print(f"Erreur survenue lors de la récupération des champs DNS du domaine ")
def saveData():
    with open("data.json", "w") as f:
        json.dump(tableauAllDatas, f, indent=4)


def analyseMisconfig():
        domainToAnalyse = input("Quel domaine voulez vous analyser (all pour tout) :")
        if domainToAnalyse == "all":
            for data in tableauAllDatas:
                checkVulnDmarc(data[0])                    
        else:
            exist = False 
            for data in tableauAllDatas:
                if data[0] == domainToAnalyse:
                    checkVulnDmarc(data[0])                    
                    exist = True
            if not exist:
                print("Le domaine n'existe pas dans votre config.")

def checkConfig():
        table = PrettyTable()
        table.field_names  = ["Domaine"]
        for data in tableauAllDatas:
            table.add_row([data[0]])
        print(table.get_string())

def printTitle():
    print(" ___  __  __   _   ___  ___   _             _                  ")   
    print("|   \\|  \\/  | /_\\ | _ \\/ __| /_\\  _ _  __ _| |_  _ ___ ___ _ _ ")
    print("| |) | |\\/| |/ _ \\|   / (__ / _ \\| ' \\/ _` | | || (_-</ -_) '_|")
    print("|___/|_|  |_/_/ \\_\\_|_\\\\___/_/ \\_\\_||_\\__,_|_|\\_, /__/\\___|_|  ")
    print("                                              |__/             ")
def addConfig():
    newElem = input("Quel est l'element que vous voulez ajouter ?")
    add = True
    for data in tableauAllDatas:
        if data[0] == newElem:
            print("L'element est déjà présent dans les assets.")
            add = False
    if add:
        dnsRecords = get_txt_records(newElem)
        if dnsRecords is not False:
            dnsRecords = sorted(dnsRecords)
            tableauAllDatas.append([newElem,dnsRecords])
            print("L'element a été ajouté avec succés !")
        saveData() 
def getDNSRecord():
    inputDomain = input("Quel est le domaine ? : ")
    if inputDomain == "all":
        for data in tableauAllDatas:
            print(colored(data[0],'red'))
            dnsRecords = get_txt_records(data[0])
            if dnsRecords is not False:
                table = PrettyTable()
                table.field_names = ["Champ"]
                
                for elem in dnsRecords:
                    table.add_row([elem])
                print(table)

    else:
        dnsRecords = get_txt_records(inputDomain)
        if dnsRecords is not False:
            table = PrettyTable()
            table.field_names = ["Champ"]
            
            for elem in dnsRecords:
                table.add_row([elem])
            print(table)
def getChangement():
    domain = input("Quel est le domaine que vous voulez voir (all pour tout) ? : ")
    check = False
    if domain == "all":
        check = True
    for data in tableauAllDatas:
        if data[0] == domain:
            check = True
    if check:
        for oldElement in assets:
            for newElement in tableauAllDatas:
                if oldElement[0] == newElement[0] and (oldElement[0] == domain or domain == "all"):
                    deletedDNSrecord = set(oldElement[1]) - set(newElement[1])
                    newDNSrecord = set(newElement[1]) - set(oldElement[1])
                    print("--------------")
                    print(f"-- {oldElement[0]} --")
                    print("--------------")
                    if bool(deletedDNSrecord) or bool(newDNSrecord):

                        if bool(newDNSrecord):
                            print("Ajout :")
                            for addElem in newDNSrecord:
                                print("- " + colored(addElem,'green'))
                        if bool(deletedDNSrecord):
                            print("Remove :")
                            for delElem in deletedDNSrecord:
                                print("- " + colored(delElem,'red')) 
                    else:
                        print("Il n'y a pas eu de changement.")
def getchr(prompt=''):
    """reads a single character"""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    # Récuperation des données dans le json
    assets = json.load(open("data.json"))

    # Nouvelles données 
    for domain in assets:
        dnsRecords = sorted(get_txt_records(domain[0]))
        tableauAllDatas.append([domain[0], dnsRecords])


    saveData()    
    inputClient = ""
    os.system('cls' if os.name == 'nt' else 'clear')

    while inputClient != "Quitter le programme":
        printTitle()
        inputClient = inquirer.list_input("Que voulez vous faire ?", choices=["analyse les misconfigurations","voir la config actuelle","Ajouter un element a la config","Voir les changements pour un domaine (ou tous)","Voir les champs DNS d'un domaine (ou tous)","Quitter le programme"])
        if inputClient == "analyse les misconfigurations":
            analyseMisconfig()
        elif inputClient == "voir la config actuelle":
            checkConfig()
        elif inputClient == "Ajouter un element a la config":
            addConfig()
        elif inputClient == "Voir les changements pour un domaine (ou tous)":
            getChangement()
        elif inputClient == "Voir les champs DNS d'un domaine (ou tous)":
            getDNSRecord()
        elif inputClient == "Quitter le programme":
            print("Thanks.")
        else:
            print("Votre commande est incorrect...")
        if inputClient != "Quitter le programme":
            print(getchr(colored("Appuyez sur n'importe quelle touche pour continuer",'yellow')))

        os.system('cls' if os.name == 'nt' else 'clear')

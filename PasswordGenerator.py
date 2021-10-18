from cryptography.fernet import Fernet
import getpass


def menu():
    print("\n1.Encrypt Password")
    print("\n2.Decrypt Password")
    print("\n3.Exit")


def EncryptPassword(key):
    try:
        password = getpass.getpass("Enter Password Here....")
        f = Fernet(key)
        print(password)
        password = bytes(password, 'utf-8')
        token = f.encrypt(password)
        print("Encrypted Password:-> "+str(token))
    except Exception as e:
        print(e)


def DecryptPassword(key):
    try:
        password = getpass.getpass("Enter Encrypted Password Here....")
        print(password)
        f = Fernet(key)
        password = bytes(password, 'utf-8')
        token = f.decrypt(password)
        print("Token" + token)
        if(str(token) == ""):
            print("Key not Found for Decrypt Password")
        else:
            print("Decrypted Password:-> "+str(token))
    except Exception as e:
        print(e)


if __name__ == "__main__":

    menu()
    try:
        f = open("KeyFile.txt", "rb")
        key = f.read()
    except Exception as e:
        key = Fernet.generate_key()
        f = open("KeyFile.txt", "wb")
        f.write(key)
    option = int(input("Enter Option:-> "))
    while(option == 1 or option == 2):
        if(option == 1):
            EncryptPassword(key)
        elif(option == 2):
            DecryptPassword(key)
        menu()
        option = int(input("Enter Option:->"))
